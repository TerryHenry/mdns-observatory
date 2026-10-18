#!/usr/bin/env python3
"""mDNS Observatory — macOS-first passive mDNS analyzer MVP."""
from __future__ import annotations
import csv, json, os, sys, time, html, threading, socket, struct, re, ipaddress
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from mdns_core import read_capture, decode_frame, DLT_EN10MB, DLT_RAW
from dnssd_browse import BonjourBrowser, DEFAULT_TYPES
from traffic_intelligence import build_traffic_intelligence
from service_correlation import build_service_chains, compare_discoveries
from session_io import validate_session_payload, restore_diagnostics
from packet_history import append_bounded, MAX_PACKET_HISTORY
from comparison_cache import comparison_cache_key
from discovery_diagnostics import summarize_discovery_events
from report_data import build_export_snapshot
from flow_analysis import build_flow_summary, filter_flow_packets, packet_service_types
from platform_diagnostics import resource_path, capture_error_guidance
from runtime_diagnostics import runtime_diagnostics, format_runtime_diagnostics
from investigation import build_investigation
from support_bundle import build_support_bundle
from capture_quality import assess_capture_quality, format_capture_quality
from capture_compare import compare_captures
from guided_troubleshooting import analyze_guided_issue, SYMPTOMS
from cause_ranking import rank_likely_causes
from temporal_analytics import analyze_temporal_discovery
from dashboard_analytics import mac_manufacturer, packet_manufacturer
from service_catalog_update import fetch_community_catalog, merge_service_catalogs, validate_cached_entries, COMMUNITY_CATALOG_SOURCE

try:
    from PySide6.QtCore import Qt, QTimer, Signal, QObject, QSettings, QRect, QMimeData, QStandardPaths
    from PySide6.QtGui import QFont, QPainter, QPen, QBrush, QColor, QFontMetrics, QPainterPath, QIcon, QLinearGradient, QRadialGradient
    from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QComboBox, QFileDialog, QTabWidget, QTableWidget, QTableWidgetItem,
        QHeaderView, QMessageBox, QLineEdit, QSplitter, QFrame, QGridLayout, QTextEdit, QProgressBar, QScrollArea, QSizePolicy, QDialog, QCheckBox, QDialogButtonBox, QFormLayout, QInputDialog)
    from PySide6.QtGui import QDrag
except ImportError:
    print("PySide6 is missing. Run ./START-MAC.command to create the environment and install dependencies.")
    raise

class SortableTableWidgetItem(QTableWidgetItem):
    """Table item that sorts numbers, percentages, IPs and timestamps naturally."""
    def __lt__(self, other):
        a = self.text().strip()
        b = other.text().strip()
        # Empty values sort before populated values in ascending order.
        if not a or a in {"—", "-"}:
            return bool(b and b not in {"—", "-"})
        if not b or b in {"—", "-"}:
            return False
        # IP addresses should sort numerically rather than lexicographically.
        try:
            return int(ipaddress.ip_address(a)) < int(ipaddress.ip_address(b))
        except ValueError:
            pass
        # Numeric columns, including packet counts, ports, byte counts and shares.
        def numeric(value):
            value = value.replace(",", "").strip()
            if value.endswith("%"):
                value = value[:-1]
            try:
                return float(value)
            except ValueError:
                return None
        na, nb = numeric(a), numeric(b)
        if na is not None and nb is not None:
            return na < nb
        # ISO date/time values sort chronologically as text in their normalized form.
        return a.casefold() < b.casefold()


APP_NAME = "mDNS Observatory"
APP_VERSION = "2.24.20"
MCAST4 = "224.0.0.251"
MCAST6 = "ff02::fb"

try:
    from scapy.all import AsyncSniffer, get_if_list, conf, Ether, IP, IPv6, UDP, DNS, DNSQR, DNSRR, Dot1Q
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False


def now_iso(): return datetime.now().astimezone().isoformat(timespec="seconds")
def app_icon_path():
    icon = "resources/mDNS-Observatory.ico" if os.name == "nt" else "resources/mDNS-Observatory.icns"
    return str(resource_path(icon, __file__))

def decode_name(value):
    if isinstance(value, bytes): return value.decode("utf-8", "replace").rstrip(".")
    return str(value or "").rstrip(".")

def rr_text(rr):
    try:
        val = rr.rdata
        if isinstance(val, bytes):
            # TXT RDATA is length-prefixed chunks; make a readable best effort.
            chunks=[]; i=0
            while i < len(val):
                n=val[i]; i+=1; chunks.append(val[i:i+n].decode('utf-8','replace')); i+=n
            return "; ".join(chunks) if chunks else ""
        if isinstance(val, (str, int)): return str(val)
        return repr(val)
    except Exception: return ""

class Analyzer:
    def __init__(self):
        self.lock=threading.RLock(); self.packets=[]; self.devices={}; self.ip_hostnames=defaultdict(set); self.services={}; self.services_by_instance={}; self.groups=Counter(); self.types=Counter(); self.events=[]; self.started=None; self.capture_thread=None; self.stop_event=threading.Event(); self.capture_error=""; self.diagnostics=Counter(); self.revision=0
    def ingest(self, pkt, source="live"):
        """Decode one captured frame. Keep diagnostics for frames that do not match."""
        with self.lock:
            self.diagnostics["frames_seen"] += 1
        if not SCAPY_OK:
            with self.lock: self.diagnostics["scapy_unavailable"] += 1
            return
        try:
            if not pkt.haslayer(UDP):
                with self.lock: self.diagnostics["not_udp"] += 1
                return
            udp = pkt[UDP]
            sport, dport = int(udp.sport), int(udp.dport)
            if sport != 5353 and dport != 5353:
                with self.lock: self.diagnostics["udp_not_port_5353"] += 1
                return
            # Some captures / link types leave the UDP payload as Raw rather than
            # automatically dissecting it as DNS. Decode the payload explicitly.
            dns = pkt.getlayer(DNS)
            if dns is None:
                try:
                    payload = bytes(udp.payload)
                    if not payload:
                        raise ValueError("empty UDP payload")
                    dns = DNS(payload)
                except Exception:
                    with self.lock: self.diagnostics["port_5353_not_decoded_as_dns"] += 1
                    return
            if pkt.haslayer(IP):
                src, dst, family = pkt[IP].src, pkt[IP].dst, "IPv4"
            elif pkt.haslayer(IPv6):
                src, dst, family = pkt[IPv6].src, pkt[IPv6].dst, "IPv6"
            else:
                src = dst = ""
                family = "unknown"
            mac = pkt[Ether].src.lower() if pkt.haslayer(Ether) else ""
            vlan = str(pkt[Dot1Q].vlan) if pkt.haslayer(Dot1Q) else "Unknown / not tagged"
            ts = float(getattr(pkt, "time", time.time()))
            stamp = datetime.fromtimestamp(ts).astimezone().isoformat(timespec="milliseconds")
            questions, records, service_names, rr_types = [], [], [], []
            q = dns.qd
            for _ in range(int(dns.qdcount or 0)):
                if not isinstance(q, DNSQR): break
                name = decode_name(q.qname); typ = int(q.qtype); t = self.qtype(typ)
                questions.append({"name": name, "type": t}); rr_types.append(t)
                q = q.payload if isinstance(q.payload, DNSQR) else None
                if q is None: break
            for section, count in (("answer", int(dns.ancount or 0)), ("authority", int(dns.nscount or 0)), ("additional", int(dns.arcount or 0))):
                rr = dns.an if section == "answer" else dns.ns if section == "authority" else dns.ar
                for _ in range(count):
                    if not isinstance(rr, DNSRR): break
                    name = decode_name(rr.rrname); typ = self.qtype(int(rr.type)); value = rr_text(rr)
                    records.append({"section": section, "name": name, "type": typ, "ttl": int(rr.ttl or 0), "value": value})
                    rr_types.append(typ)
                    if name.endswith("._tcp.local") or name.endswith("._udp.local"): service_names.append(name)
                    rr = rr.payload if isinstance(rr.payload, DNSRR) else None
                    if rr is None: break
            if not questions and not records:
                with self.lock: self.diagnostics["dns_without_questions_or_records"] += 1
                return
            direction = "Query" if int(dns.qr) == 0 else "Response"
            info = {"time": stamp, "timestamp": ts, "source": src, "destination": dst, "mac": mac, "vlan": vlan,
                    "family": family, "sport": sport, "dport": dport, "direction": direction, "id": int(dns.id or 0),
                    "questions": questions, "records": records, "rr_types": sorted(set(rr_types)),
                    "services": sorted(set(service_names)), "source_type": source, "bytes": len(pkt)}
            self.ingest_decoded(info)
        except Exception as e:
            with self.lock:
                self.capture_error = str(e)
                self.diagnostics["decode_errors"] += 1
    def ingest_live(self, pkt):
        """Decode live Scapy frames with the same deterministic decoder as file imports.

        Do not depend on Scapy's guessed UDP/DNS layer tree: macOS BPF captures can
        expose payloads differently from packets decoded from PCAP files.
        """
        with self.lock:
            self.diagnostics["frames_seen"] += 1
        try:
            raw = bytes(pkt)
            # Scapy may already have dissected the frame, but the bytes are the
            # source of truth for our decoder. Most macOS physical interfaces use
            # Ethernet framing; raw IP is handled as a fallback.
            if SCAPY_OK and pkt.haslayer(Ether):
                linktype = DLT_EN10MB
            elif raw and (raw[0] >> 4) in (4, 6):
                linktype = DLT_RAW
            else:
                # Scapy's L2 class is useful for diagnostics on unsupported link types.
                with self.lock:
                    self.diagnostics["live_unsupported_linktype"] += 1
                    self.diagnostics["live_last_packet_layer"] = type(pkt).__name__
                return
            ts = float(getattr(pkt, "time", time.time()))
            info = decode_frame(raw, linktype, ts)
            if info is None:
                with self.lock:
                    self.diagnostics["live_non_mdns_or_unparsed"] += 1
                    # Scapy layer detection is diagnostic only; it never gates decoding.
                    if SCAPY_OK and pkt.haslayer(UDP):
                        udp = pkt[UDP]
                        if int(udp.sport) == 5353 or int(udp.dport) == 5353:
                            self.diagnostics["live_port_5353_not_decoded"] += 1
                return
            if info.get("capture_origin") != "erspan":
                info["source_type"] = "local"
                info["capture_origin"] = "local"
            info["capture_method"] = "live"
            self.ingest_decoded(info)
        except Exception as e:
            with self.lock:
                self.capture_error = str(e)
                self.diagnostics["live_decode_errors"] += 1

    def ingest_decoded(self, info):
        """Store an already-decoded packet using the shared live/import pipeline."""
        with self.lock:
            self.diagnostics["mdns_packets_accepted"] += 1
            self.revision += 1
            removed = append_bounded(self.packets, info, MAX_PACKET_HISTORY)
            if removed:
                self.diagnostics["packet_history_truncated"] += removed
            src, dst, mac, vlan = info["source"], info["destination"], info["mac"], info["vlan"]
            stamp, direction = info["time"], info["direction"]
            self.groups[dst] += 1
            for typ in info["rr_types"]: self.types[typ] += 1
            if src:
                dev = self.devices.setdefault(src, {"ip": src, "mac": mac, "vlan": vlan, "first_seen": stamp, "last_seen": stamp,
                    "packets": 0, "queries": 0, "responses": 0, "hostnames": set(self.ip_hostnames.get(src, set())), "services": set()})
                dev["last_seen"] = stamp; dev["packets"] += 1; dev["mac"] = dev["mac"] or mac
                dev["vlan"] = vlan if dev["vlan"] in ("Unknown / not tagged", "") else dev["vlan"]
                dev["queries"] += direction == "Query"; dev["responses"] += direction == "Response"
                for question in info["questions"]:
                    if question["name"].endswith(".local"): dev["hostnames"].add(question["name"])
                for rec in info["records"]:
                    if rec["type"] in ("A", "AAAA"):
                        hostname, address = rec.get("name", "").rstrip("."), rec.get("value", "").strip()
                        # DNS-SD address records associate the owner hostname with the
                        # address in RDATA, which is often not the packet's source IP.
                        if hostname.endswith(".local") and address:
                            self.ip_hostnames[address].add(hostname)
                            addressed_device = self.devices.get(address)
                            if addressed_device is not None:
                                addressed_device["hostnames"].add(hostname)
                    if "._tcp.local" in rec["name"] or "._udp.local" in rec["name"]: dev["services"].add(rec["name"])
            for rec in info["records"]:
                if rec["type"] == "PTR" and ("._tcp.local" in rec["name"] or "._udp.local" in rec["name"]):
                    key = rec["value"] or rec["name"]
                    svc = self.services.setdefault(key, {"instance": key, "service_type": rec["name"], "target": "", "port": "", "txt": [],
                        "first_seen": stamp, "last_seen": stamp, "records": 0, "sources": set()})
                    self.services_by_instance[key] = svc
                    svc["last_seen"] = stamp; svc["records"] += 1; svc["sources"].add(src)
            for rec in info["records"]:
                if rec["type"] == "SRV":
                    svc = self.services_by_instance.get(rec["name"])
                    if svc is not None:
                        svc["target"] = rec["value"]
                        match = re.search(r"\bport=(\d+)\b", rec["value"])
                        if match: svc["port"] = match.group(1)
                elif rec["type"] == "TXT":
                    svc = self.services_by_instance.get(rec["name"])
                    if svc is not None and rec["value"] not in svc["txt"]:
                        svc["txt"].append(rec["value"])

    @staticmethod
    def qtype(t):
        return {1:"A",12:"PTR",16:"TXT",28:"AAAA",33:"SRV",255:"ANY",5:"CNAME",47:"NSEC",41:"OPT"}.get(t,f"TYPE{t}")
    def clear(self):
        with self.lock:
            self.packets.clear(); self.devices.clear(); self.ip_hostnames.clear(); self.services.clear(); self.services_by_instance.clear(); self.groups.clear(); self.types.clear(); self.events.clear(); self.diagnostics.clear(); self.capture_error=""; self.started=now_iso(); self.revision += 1
    def snapshot(self, include_packets=True):
        with self.lock:
            dev=[]
            for d in self.devices.values(): dev.append({**d,"hostnames":sorted(d["hostnames"]),"services":sorted(d["services"])})
            svc=[{**s,"sources":sorted(s["sources"])} for s in self.services.values()]
            return {"app":APP_NAME,"generated_at":now_iso(),"capture_started":self.started,"packet_count":len(self.packets),"stored_packet_count":len(self.packets),"packet_history_truncated":bool(self.diagnostics.get("packet_history_truncated", 0)),"packets":list(self.packets) if include_packets else [],"devices":dev,"services":svc,"groups":dict(self.groups),"record_types":dict(self.types),"capture_error":self.capture_error,"diagnostics":dict(self.diagnostics),"revision":self.revision}
    def recent_packets(self, limit=20000):
        """Return a bounded recent packet window for responsive chart rendering."""
        with self.lock:
            return list(self.packets[-max(1, int(limit)):])

class Bus(QObject):
    changed=Signal()
    status=Signal(str)
    discovery_event=Signal(dict)
    capture_finished=Signal(str)
    discovery_finished=Signal()
    catalog_update_finished=Signal(object)



class VisualPanel(QWidget):
    """Compact custom-painted analytics panel; no plotting dependency required."""
    selected = Signal(str, str)
    def __init__(self, title, subtitle="", kind="line", parent=None):
        super().__init__(parent)
        self.title=title; self.subtitle=subtitle; self.kind=kind; self.data=[]; self.hitboxes=[]
        self.empty_message="Import a capture or start live monitoring to populate this chart."
        self.drilldown_category="source"; self.zoom_factor=1.0
        self.setMinimumHeight(285)
        self.setStyleSheet("background:#141c26;border:1px solid #344255;border-radius:12px;")
    def set_data(self, data):
        self.data=list(data or [])
        self.update()
    def mousePressEvent(self, event):
        pos=event.position().toPoint()
        for rect,label,category in self.hitboxes:
            if rect.contains(pos): self.selected.emit(str(label),str(category)); return
        super().mousePressEvent(event)
    def paintEvent(self, event):
        self.hitboxes=[]
        p=QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r=self.rect()
        # Deep, layered surface with a subtle top-edge glow.
        bg=QLinearGradient(0,0,0,r.height()); bg.setColorAt(0,QColor('#172231')); bg.setColorAt(1,QColor('#111923'))
        p.setPen(QPen(QColor('#2b3a4e'),1)); p.setBrush(QBrush(bg)); p.drawRoundedRect(r.adjusted(0,0,-1,-1),14,14)
        glow=QLinearGradient(0,0,r.width(),0); glow.setColorAt(0,QColor('#ff914d')); glow.setColorAt(.52,QColor('#4e9ee8')); glow.setColorAt(1,QColor('#61c7a5'))
        p.setPen(QPen(QBrush(glow),2)); p.drawLine(16,2,max(16,r.width()-16),2)
        p.setPen(QColor('#f3f6fb')); p.setFont(QFont('SF Pro Text',12,QFont.Weight.DemiBold)); p.drawText(18,28,self.title)
        p.setPen(QColor('#8fa2b8')); p.setFont(QFont('SF Pro Text',9)); p.drawText(18,49,self.subtitle)
        area=r.adjusted(20,65,-18,-25)
        if area.width()<30 or area.height()<30: p.end(); return
        if not self.data:
            p.setPen(QColor('#8495aa')); p.drawText(area,Qt.AlignmentFlag.AlignCenter,self.empty_message)
            p.end(); return
        accent=QColor('#ff914d'); blue=QColor('#4e9ee8'); mint=QColor('#61c7a5')
        if self.kind=='line':
            vals=[max(0,float(x[1])) for x in self.data]; maxv=max(vals+[1]); n=len(vals); points=[]
            for i,v in enumerate(vals):
                x=area.left()+area.width()*(i/max(1,n-1)); y=area.bottom()-8-(v/maxv)*(area.height()-28)
                points.append((int(x),int(y)))
            # Fine grid and quiet value guides.
            p.setFont(QFont('SF Pro Text',8)); p.setPen(QPen(QColor('#263548'),1,Qt.PenStyle.DashLine))
            for k in range(4):
                y=int(area.top()+10+(area.height()-32)*k/3); p.drawLine(int(area.left()),y,int(area.right()),y)
                p.setPen(QColor('#71849a')); p.drawText(int(area.left()+2),y-4,f'{maxv*(1-k/3):.0f}'); p.setPen(QPen(QColor('#263548'),1,Qt.PenStyle.DashLine))
            if len(points)>1:
                path=QPainterPath(); path.moveTo(*points[0])
                for pt in points[1:]: path.lineTo(*pt)
                fill=QPainterPath(path); fill.lineTo(points[-1][0],area.bottom()-8); fill.lineTo(points[0][0],area.bottom()-8); fill.closeSubpath()
                grad=QLinearGradient(0,area.top(),0,area.bottom()); grad.setColorAt(0,QColor(255,145,77,100)); grad.setColorAt(1,QColor(255,145,77,0))
                p.setPen(Qt.PenStyle.NoPen); p.setBrush(QBrush(grad)); p.drawPath(fill)
                p.setPen(QPen(QColor(255,145,77,45),7)); p.setBrush(Qt.BrushStyle.NoBrush); p.drawPath(path)
                p.setPen(QPen(accent,2.5)); p.drawPath(path)
            p.setBrush(QBrush(accent)); p.setPen(QPen(QColor('#fff0e5'),1))
            for x,y in points[-12:]: p.drawEllipse(x-3,y-3,6,6)
            for i,(x,y) in enumerate(points): self.hitboxes.append((QRect(x-9,y-9,18,18),str(self.data[i][0]),self.drilldown_category))
            p.setPen(QColor('#a6b6c9')); p.setFont(QFont('SF Pro Text',8)); p.drawText(int(area.left()),int(area.bottom()+13),str(self.data[0][0])); p.drawText(int(area.right()-55),int(area.bottom()+13),str(self.data[-1][0]))
            p.setPen(QColor('#ffb27f')); p.setFont(QFont('SF Pro Text',9,QFont.Weight.DemiBold)); p.drawText(int(area.right()-110),int(area.top()+10),f'PEAK  {int(maxv):,}')
        elif self.kind=='bars':
            items=self.data[:8]; maxv=max([float(x[1]) for x in items]+[1]); gap=8; bh=max(12,(area.height()-gap*(len(items)-1))/max(1,len(items)))
            p.setFont(QFont('SF Pro Text',9))
            for i,item in enumerate(items):
                label,val=item[0],item[1]; y=int(area.top()+i*(bh+gap)); trackw=int(area.width()*.70); width=max(3,int(trackw*float(val)/maxv))
                self.hitboxes.append((QRect(int(area.left()),y,int(area.width()),int(bh)),str(label),self.drilldown_category))
                p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor('#202d3d')); p.drawRoundedRect(int(area.left()),y,trackw,int(bh),6,6)
                grad=QLinearGradient(area.left(),y,area.left()+max(4,width),y+bh); grad.setColorAt(0,QColor('#ff914d')); grad.setColorAt(1,QColor('#e86c46' if i%2==0 else '#4e9ee8'))
                p.setBrush(QBrush(grad)); p.drawRoundedRect(int(area.left()),y,width,int(bh),6,6)
                # End cap gives the bar a crisp, luminous finish.
                p.setBrush(QColor('#ffd0ae' if i%2==0 else '#a7d8ff')); p.drawEllipse(int(area.left())+width-3,y+int(bh/2)-3,6,6)
                p.setPen(QColor('#eaf0f7')); p.drawText(int(area.left()+trackw+10),y+int(bh*.43),str(label)[:26])
                p.setPen(QColor('#ffbd91')); p.setFont(QFont('SF Pro Text',9,QFont.Weight.DemiBold)); p.drawText(int(area.left()+trackw+10),y+int(bh*.83),f'{val:,}' if isinstance(val,int) else str(val)); p.setFont(QFont('SF Pro Text',9))
        elif self.kind=='donut':
            total=sum(float(x[1]) for x in self.data) or 1
            colors=['#ff914d','#4e9ee8','#61c7a5','#b69cff','#e7c35a','#e7799b','#49c8d8']
            side=int(min(area.height()-8,area.width()*.43)); side=max(50,side); x=int(area.left()+4); y=int(area.center().y()-side/2); start=90*16
            # Dark inset disc makes the donut feel dimensional without obscuring labels.
            for i,(_,v) in enumerate(self.data):
                span=int(float(v)/total*360*16); p.setPen(QPen(QColor('#111923'),3)); p.setBrush(QColor(colors[i%len(colors)])); p.drawPie(x,y,side,side,start,-span); start-=span
            hole=int(side*.62); hx=x+(side-hole)//2; hy=y+(side-hole)//2
            p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor('#151f2c')); p.drawEllipse(hx,hy,hole,hole)
            p.setPen(QColor('#f4f7fb')); p.setFont(QFont('SF Pro Text',15,QFont.Weight.Bold)); p.drawText(QRect(hx,hy+hole//2-18,hole,25),Qt.AlignmentFlag.AlignCenter,f'{int(total):,}')
            p.setPen(QColor('#8fa2b8')); p.setFont(QFont('SF Pro Text',8,QFont.Weight.DemiBold)); p.drawText(QRect(hx,hy+hole//2+5,hole,15),Qt.AlignmentFlag.AlignCenter,'TOTAL')
            p.setFont(QFont('SF Pro Text',9))
            lx=int(area.left()+side+24); max_label_w=max(40,int(area.right()-lx-4))
            for i,(label,val) in enumerate(self.data[:7]):
                yy=int(area.top()+i*22); p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(colors[i%len(colors)])); p.drawRoundedRect(lx,yy+2,9,9,3,3)
                p.setPen(QColor('#e4ebf4')); p.drawText(lx+17,yy+11,str(label)[:24])
                p.setPen(QColor('#a8bad0')); p.drawText(lx+17,yy+21 if yy+21<area.bottom() else yy+11,f'{val:,}' if isinstance(val,int) else str(val))
                self.hitboxes.append((QRect(lx-3,yy,max_label_w,21),str(label),self.drilldown_category))
        elif self.kind=='network':
            cx=int(area.center().x()); cy=int(area.center().y()); rad=min(area.width(),area.height())*.39*self.zoom_factor; nodes=self.data[:22]; n=max(1,len(nodes))
            radial=QRadialGradient(cx,cy,rad*1.45); radial.setColorAt(0,QColor(78,158,232,22)); radial.setColorAt(1,QColor(78,158,232,0)); p.setPen(Qt.PenStyle.NoPen); p.setBrush(QBrush(radial)); p.drawEllipse(int(cx-rad*1.45),int(cy-rad*1.45),int(rad*2.9),int(rad*2.9))
            p.setBrush(Qt.BrushStyle.NoBrush); p.setPen(QPen(QColor('#27384b'),1,Qt.PenStyle.DashLine)); p.drawEllipse(int(cx-rad),int(cy-rad),int(rad*2),int(rad*2))
            for i,item in enumerate(nodes):
                angle=(-__import__('math').pi/2)+(i*2*__import__('math').pi/n); x=int(cx+rad*__import__('math').cos(angle)); y=int(cy+rad*__import__('math').sin(angle)); color=QColor('#ff914d' if len(item)>2 and item[2]=='service' else '#4e9ee8')
                p.setPen(QPen(QColor(color.red(),color.green(),color.blue(),100),1.4)); p.drawLine(cx,cy,x,y)
                p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(color.red(),color.green(),color.blue(),35)); p.drawEllipse(x-13,y-13,26,26); p.setBrush(QBrush(color)); p.drawEllipse(x-5,y-5,10,10)
                label=str(item[0]); p.setPen(QColor('#dce7f3')); p.setFont(QFont('SF Pro Text',9 if self.width()>700 else 8,QFont.Weight.Medium)); fm=QFontMetrics(p.font()); label_w=min(max(110,fm.horizontalAdvance(label)+8),max(110,int(area.width()*.30)))
                # Anchor labels outwards from the ring; keep them on-screen and avoid drawing through the node.
                if abs(x-cx)<rad*.22: tx=x-label_w//2; align=Qt.AlignmentFlag.AlignHCenter
                elif x<cx: tx=max(int(area.left()),x-label_w-12); align=Qt.AlignmentFlag.AlignRight
                else: tx=min(int(area.right()-label_w),x+14); align=Qt.AlignmentFlag.AlignLeft
                ty=max(int(area.top()+12),min(int(area.bottom()-5),y+4)); p.drawText(QRect(tx,ty-12,label_w,20),int(align)|int(Qt.AlignmentFlag.AlignVCenter),label if fm.horizontalAdvance(label)<=label_w else fm.elidedText(label,Qt.TextElideMode.ElideMiddle,label_w))
                self.hitboxes.append((QRect(x-16,y-16,32,32),label,self.drilldown_category))
            p.setPen(QPen(QColor('#ffb27f'),2)); p.setBrush(QColor('#182636')); p.drawEllipse(cx-22,cy-22,44,44); p.setPen(QColor('#ffbd91')); p.setFont(QFont('SF Pro Text',8,QFont.Weight.Bold)); p.drawText(cx-19,cy+4,'mDNS')
        p.end()

class DeviceActivityDialog(QDialog):
    """Large, searchable device activity graph with selectable node details."""
    def __init__(self, data, parent=None):
        super().__init__(parent); self.setWindowTitle("Device activity · mDNS Observatory"); self.resize(1100,760); self.setMinimumSize(760,520)
        self.all_data=list(data or []); self.layout_root=QVBoxLayout(self); self.layout_root.setContentsMargins(14,14,14,14); self.layout_root.setSpacing(10)
        toolbar=QHBoxLayout(); toolbar.addWidget(QLabel("Find device")); self.search=QLineEdit(); self.search.setPlaceholderText("Search hostname or IP…"); toolbar.addWidget(self.search,1)
        self.fit_btn=QPushButton("Fit graph"); self.fit_btn.setObjectName("secondary"); toolbar.addWidget(self.fit_btn)
        toolbar.addWidget(QLabel("Zoom")); self.zoom=QComboBox(); self.zoom.addItems(["75%","100%","125%","150%"]); self.zoom.setCurrentText("100%"); toolbar.addWidget(self.zoom)
        self.layout_root.addLayout(toolbar)
        self.graph=VisualPanel("Device activity","Select a node to inspect its observed activity","network"); self.graph.setToolTip("Expanded view of the dashboard's Device activity graph. Node size reflects packet volume in the selected window; it is not a physical or routed network map."); self.graph.setMinimumHeight(420); self.graph.setSizePolicy(QSizePolicy.Policy.Expanding,QSizePolicy.Policy.Expanding); self.layout_root.addWidget(self.graph,1)
        self.details=QLabel("Select a device node to see its observed packet count."); self.details.setWordWrap(True); self.details.setStyleSheet("background:#19222e;border:1px solid #344255;border-radius:8px;padding:12px;color:#dce7f3;"); self.layout_root.addWidget(self.details)
        self.graph.selected.connect(self.show_device); self.search.textChanged.connect(self.apply_search); self.zoom.currentTextChanged.connect(self.apply_zoom); self.fit_btn.clicked.connect(self.fit_graph); self.apply_search("")
    def apply_search(self, text):
        q=str(text or "").casefold(); self.graph.set_data([item for item in self.all_data if q in str(item[0]).casefold()])
        self.details.setText(f"Showing {len(self.graph.data)} of {len(self.all_data)} devices. Select a node for details.")
    def apply_zoom(self, value):
        self.graph.zoom_factor={"75%":0.75,"100%":1.0,"125%":1.25,"150%":1.5}.get(value,1.0); self.graph.update()
    def fit_graph(self):
        self.zoom.setCurrentText("100%"); self.graph.zoom_factor=1.0; self.graph.update()
    def show_device(self, label, category):
        item=next((x for x in self.graph.data if str(x[0])==str(label)),None)
        if item is None: self.details.setText(str(label)); return
        count=item[1] if len(item)>1 else "—"
        self.details.setText(f"<b>{html.escape(str(label))}</b><br>Observed source activity: <b>{html.escape(str(count))}</b> packets in the dashboard chart window.<br><span style='color:#9eacbd'>Detailed service and packet evidence remains available in the Devices and Packet Evidence views.</span>")


class ServiceExplanationDialog(QDialog):
    """Show plain-language purpose and capture evidence for observed services."""
    def __init__(self, services, catalog, context="", parent=None):
        super().__init__(parent)
        self.services=list(services or [])
        self.catalog_by_type={self.normalize_type(item.get("type")):item for item in (catalog or []) if item.get("type")}
        self.setWindowTitle("Service explanations · mDNS Observatory")
        self.resize(980,680); self.setMinimumSize(720,480)
        layout=QVBoxLayout(self); layout.setContentsMargins(14,14,14,14); layout.setSpacing(9)
        if context:
            heading=QLabel(context); heading.setWordWrap(True); heading.setObjectName("sub"); layout.addWidget(heading)
        self.table=QTableWidget(0,6)
        self.table.setHorizontalHeaderLabels(["Service instance","DNS-SD type","Target","Port","TXT metadata","Advertised by"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True); self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True); self.table.setMinimumHeight(210)
        for service in self.services:
            sources=service.get("sources", []) or []
            if isinstance(sources, set): sources=sorted(sources)
            cells=[service.get("instance",""),service.get("service_type",""),service.get("target","") or "—",service.get("port","") or "—"," | ".join(map(str,service.get("txt",[]) or [])) or "—",", ".join(map(str,sources)) or "—"]
            row=self.table.rowCount(); self.table.insertRow(row)
            for column,value in enumerate(cells):
                item=QTableWidgetItem(str(value)); item.setToolTip(str(value)); self.table.setItem(row,column,item)
        layout.addWidget(self.table,2)
        layout.addWidget(QLabel("What it does and what the capture shows"))
        self.details=QTextEdit(); self.details.setReadOnly(True); self.details.setMinimumHeight(150); layout.addWidget(self.details,1)
        close=QPushButton("Close"); close.setObjectName("secondary"); close.clicked.connect(self.accept)
        buttons=QHBoxLayout(); buttons.addStretch(1); buttons.addWidget(close); layout.addLayout(buttons)
        self.table.currentCellChanged.connect(self.update_details)
        if self.services:
            self.table.selectRow(0); self.table.setCurrentCell(0,0); self.update_details(0,0, -1,-1)
        else:
            self.details.setPlainText("No service advertisements or matching DNS-SD targets for this device were observed in the current capture. This does not prove the device offers no services: the capture may be partial, or the service may not have been advertised during the observation window.")

    @staticmethod
    def normalize_type(value):
        return str(value or "").strip().lower().rstrip(".").removesuffix(".local")

    def update_details(self, row, _column, _old_row, _old_column):
        if row < 0 or row >= len(self.services): return
        service=self.services[row]; service_type=str(service.get("service_type") or "Unknown")
        catalog=self.catalog_by_type.get(self.normalize_type(service_type), {})
        friendly=catalog.get("name") or service_type
        purpose=catalog.get("description") or (f"No catalog description is available for {service_type}. The DNS-SD type identifies an advertised application protocol; inspect its SRV target, port, TXT metadata, and packet evidence to determine its exact role.")
        sources=service.get("sources", []) or []
        if isinstance(sources, set): sources=sorted(sources)
        lines=[friendly, f"DNS-SD type: {service_type}", f"What it usually does: {purpose}", "", "Observed in this capture:",
               f"• Instance: {service.get('instance') or '—'}",
               f"• Target and port: {(service.get('target') or 'target not observed') + (':' + str(service.get('port')) if service.get('port') else '')}",
               f"• PTR observations: {service.get('records', '—')}",
               f"• Advertised by source IPs: {', '.join(map(str,sources)) or 'not identified'}",
               f"• TXT metadata: {' | '.join(map(str,service.get('txt',[]) or [])) or 'not observed'}",
               f"• First / last seen: {service.get('first_seen') or '—'} / {service.get('last_seen') or '—'}",
               "", "An advertisement shows that this service was announced in the captured traffic; it does not prove a client used it or that it was reachable."]
        self.details.setPlainText("\n".join(lines))


class DashboardPanelCard(QFrame):
    """Draggable dashboard card; chart interaction remains inside the chart widget."""
    def __init__(self, name, widget, dashboard):
        super().__init__(); self.panel_name=name; self.dashboard=dashboard; self.setObjectName("metric")
        self.setAcceptDrops(True); self.setFrameShape(QFrame.Shape.StyledPanel)
        root=QVBoxLayout(self); root.setContentsMargins(8,7,8,8); root.setSpacing(5)
        head=QHBoxLayout(); head.setSpacing(8)
        self.handle=QLabel("⠿")
        self.handle.setObjectName("dashboardDragHandle")
        self.handle.setToolTip("Drag this grip and drop the panel onto another panel to change its position")
        self.handle.setCursor(Qt.CursorShape.OpenHandCursor)
        self.handle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.handle.setMinimumWidth(28); self.handle.setMaximumWidth(32)
        self.handle.setStyleSheet("QLabel#dashboardDragHandle { color:#aebdce; background:transparent; border:1px solid transparent; border-radius:5px; font-size:19px; font-weight:600; padding:2px 3px; } QLabel#dashboardDragHandle:hover { color:#ff9858; background:#263445; border:1px solid #f5823a; }")
        head.addWidget(self.handle,1); root.addLayout(head); root.addWidget(widget,1)
        # Qt delivers drop events to the child chart under the pointer, not always
        # to the containing card. Install the filter on the card, handle and chart.
        self.handle.installEventFilter(self)
        widget.installEventFilter(self)
        widget.setAcceptDrops(True)
        self._drag_start=None
    def eventFilter(self,obj,event):
        et=event.type()
        if obj is self.handle and et==event.Type.MouseButtonPress and event.button()==Qt.MouseButton.LeftButton:
            self._drag_start=event.position().toPoint(); return False
        if obj is self.handle and et==event.Type.MouseMove and event.buttons() & Qt.MouseButton.LeftButton:
            if self._drag_start is not None and (event.position().toPoint()-self._drag_start).manhattanLength()>8:
                drag=QDrag(self); mime=QMimeData(); mime.setText(self.panel_name); drag.setMimeData(mime)
                drag.exec(Qt.DropAction.MoveAction); self._drag_start=None; return True
        if et in (event.Type.DragEnter, event.Type.DragMove):
            if event.mimeData().hasText() and event.mimeData().text() in self.dashboard.panel_cards:
                event.acceptProposedAction(); return True
        if et==event.Type.Drop:
            source=event.mimeData().text()
            if source in self.dashboard.panel_cards and source != self.panel_name:
                self.dashboard.move_panel(source,self.panel_name); event.acceptProposedAction(); return True
        return super().eventFilter(obj,event)
    def dragEnterEvent(self,event):
        if event.mimeData().hasText() and event.mimeData().text() in self.dashboard.panel_cards: event.acceptProposedAction()
    def dragMoveEvent(self,event):
        if event.mimeData().hasText() and event.mimeData().text() in self.dashboard.panel_cards: event.acceptProposedAction()
    def dropEvent(self,event):
        source=event.mimeData().text()
        if source in self.dashboard.panel_cards and source != self.panel_name:
            self.dashboard.move_panel(source,self.panel_name); event.acceptProposedAction()


class Dashboard(QWidget):
    selected = Signal(str, str)
    CHART_WINDOW = 10000
    def __init__(self,parent=None):
        super().__init__(parent)
        outer=QVBoxLayout(self); outer.setContentsMargins(0,0,0,0); outer.setSpacing(0)
        scroll=QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.Shape.NoFrame); outer.addWidget(scroll)
        content=QWidget(); lay=QVBoxLayout(content); lay.setContentsMargins(12,12,12,12); lay.setSpacing(12); scroll.setWidget(content)
        controls=QHBoxLayout(); controls.addWidget(QLabel("Time range"))
        self.time_range=QComboBox(); self.time_range.addItems(["All captured time","Last 5 minutes","Last 15 minutes","Last hour"]); self.time_range.setToolTip("Limit passive packet charts to a recent window, measured back from the newest packet timestamp in the capture."); controls.addWidget(self.time_range)
        controls.addWidget(QLabel("Filter")); self.filter_text=QLineEdit(); self.filter_text.setPlaceholderText("Filter IP, service, destination, VLAN or record…"); self.filter_text.setToolTip("Filter the passive packet charts by matching IPs, service names, destinations, VLANs, DNS record names, and related packet details. Active Bonjour discovery charts are independent."); controls.addWidget(self.filter_text,1)
        self.customize_btn=QPushButton("Customize dashboard…"); self.customize_btn.setObjectName("secondary"); controls.addWidget(self.customize_btn)
        self.discovery_btn=QPushButton("Start active discovery"); self.discovery_btn.setToolTip("Start or stop live Bonjour (DNS-SD) service browsing. This is independent of passive packet capture and does not transmit test traffic."); controls.addWidget(self.discovery_btn)
        if sys.platform != "darwin":
            self.discovery_btn.setText("Active discovery (macOS only)")
            self.discovery_btn.setToolTip("Active Bonjour browsing currently uses Apple's native DNS-SD library and is available on macOS only. Passive capture and PCAP analysis are available on Windows.")
            self.discovery_btn.setEnabled(False)
        self.summary=QLabel("Live traffic insights · click a source or destination bar to investigate"); self.summary.setStyleSheet("color:#aab7c7;padding:4px 2px;")
        self.drilldown_banner=QFrame()
        self.drilldown_banner.setObjectName("metric")
        banner_layout=QHBoxLayout(self.drilldown_banner); banner_layout.setContentsMargins(12,7,12,7)
        self.drilldown_label=QLabel("No dashboard drill-down active")
        self.drilldown_label.setWordWrap(True)
        self.drilldown_label.setStyleSheet("color:#c7d3e2;")
        self.view_packets_btn=QPushButton("View matching packets")
        self.view_packets_btn.setObjectName("secondary")
        self.view_packets_btn.setToolTip("Open the packet table with this drill-down applied")
        self.clear_drilldown_btn=QPushButton("Clear drill-down")
        self.clear_drilldown_btn.setObjectName("secondary")
        self.clear_drilldown_btn.setToolTip("Remove the dashboard selection and restore the full packet view")
        self.clear_drilldown_btn.clicked.connect(self.clear_drilldown)
        banner_layout.addWidget(self.drilldown_label,1); banner_layout.addWidget(self.view_packets_btn); banner_layout.addWidget(self.clear_drilldown_btn)
        self.drilldown_banner.setVisible(False)
        lay.addLayout(controls); lay.addWidget(self.summary); lay.addWidget(self.drilldown_banner)
        # KPI strip remains fixed; individual charts below are draggable cards.
        active_kpis=QGridLayout(); active_kpis.setHorizontalSpacing(10); active_kpis.setVerticalSpacing(8)
        self.active_kpi_labels={}
        kpi_tooltips={
            "active":"Service instances currently present in active Bonjour browse results. This is separate from passive packet counts.",
            "resolved":"Active instances for which Bonjour returned resolution details such as a target host and port. Resolved does not guarantee the service is reachable.",
            "types":"Distinct DNS-SD service types currently returned by active Bonjour browsing, such as _ipp._tcp.",
            "errors":"Bonjour browse or resolve errors recorded during active discovery. This is not a count of failed passive mDNS packets.",
        }
        for i,(key,label,accent) in enumerate([
            ("active","Active instances","#ff914d"),("resolved","Resolved","#61c7a5"),
            ("types","Service types","#4e9ee8"),("errors","Discovery errors","#e7799b")]):
            frame=QFrame(); frame.setObjectName("metric"); fl=QVBoxLayout(frame); fl.setContentsMargins(16,12,16,12)
            value=QLabel("0"); value.setObjectName("metricValue"); value.setStyleSheet(f"color:{accent};font-size:25px;font-weight:700;")
            value.setToolTip(kpi_tooltips[key])
            caption=QLabel(label); caption.setObjectName("metricLabel"); fl.addWidget(value); fl.addWidget(caption)
            active_kpis.addWidget(frame,0,i); self.active_kpi_labels[key]=value
        lay.addLayout(active_kpis)
        self.traffic=VisualPanel("Live mDNS traffic","Passive capture only · packet activity over time","line"); self.traffic.setMinimumHeight(330)
        self.traffic.setToolTip("Packet counts per minute from the passive capture. This is observed mDNS traffic, not the number of services found by Bonjour discovery. Select a point to inspect that minute.")
        self.topology=VisualPanel("Device activity","Top source devices · expand this graph above for details","network"); self.topology.setMinimumHeight(300)
        self.topology.setToolTip("Shows the most active source IPs in the selected packet window. Node size reflects observed packet volume; it does not show a network topology or prove that devices can reach one another.")
        self.groups=VisualPanel("Multicast destinations","Select a bar to filter traffic","bars"); self.groups.setMinimumHeight(280)
        self.groups.setToolTip("Destination addresses seen in the selected passive packet window. mDNS normally uses 224.0.0.251 (IPv4) or ff02::fb (IPv6). Counts are packets, not unique services.")
        self.records=VisualPanel("DNS record mix","Queries and advertised record types","donut"); self.records.setMinimumHeight(280)
        self.records.setToolTip("Counts DNS questions and records in the selected passive packet window. PTR discovers service types or instances; SRV gives a service target host and port; TXT carries service metadata; A maps a host to IPv4; AAAA maps it to IPv6. Labels beginning “Query ” are questions, not answers. Counts are observations, not unique devices or services.")
        self.sources=VisualPanel("Top talkers","Select a source to investigate","bars"); self.sources.setMinimumHeight(280)
        self.sources.setToolTip("Source IPs ranked by packet count in the selected passive packet window. A source may be a device, relay, or mirror point; the capture cannot always identify the originating device.")
        self.packet_sizes=VisualPanel("Packet size distribution","Observed frame sizes in the chart window · bytes","bars"); self.packet_sizes.setMinimumHeight(260)
        self.packet_sizes.setToolTip("Counts captured frames by observed length. This is frame size, not DNS payload size or network throughput.")
        self.dns_names=VisualPanel("Most advertised DNS-SD names","PTR/service names observed in captured records","bars"); self.dns_names.setMinimumHeight(260)
        self.dns_names.setToolTip("Shows PTR record names advertised in passive packets. A name such as _ipp._tcp.local identifies a service type (IPP printing); “Office Printer._ipp._tcp.local” identifies one advertised service instance. These are DNS-SD service names, not necessarily device hostnames, and repeated packets can increase counts.")
        self.active_types_chart=VisualPanel("Active discovery · service types","Bonjour browse results · not packet counts","bars"); self.active_types_chart.setMinimumHeight(260)
        self.active_types_chart.setToolTip("Counts service types returned by active macOS Bonjour browsing, such as _airplay._tcp or _ipp._tcp. This is a live browse result count, not a packet count; it is independent of the passive Traffic Source filter.")
        self.active_status_chart=VisualPanel("Resolution health","Current active instances by state","donut"); self.active_status_chart.setMinimumHeight(260)
        self.active_status_chart.setToolTip("Resolved means Bonjour returned the service target and connection details, such as host and port. Resolving means the service instance was discovered but those details are not complete yet. Error means resolution failed. These are lookup states, not a health check or proof that the service is reachable.")
        self.packets_per_second=VisualPanel("mDNS packets per second","Passive capture rate · selected traffic source","line"); self.packets_per_second.setMinimumHeight(260)
        self.packets_per_second.setToolTip("Counts captured mDNS packets in each second of the selected packet window. Gaps can mean no packets or missing timestamps; this is not a bandwidth measure.")
        self.manufacturer_chart=VisualPanel("mDNS by manufacturer","Packet counts by inferred source manufacturer · unknowns remain visible","bars"); self.manufacturer_chart.setMinimumHeight(260)
        self.manufacturer_chart.setToolTip("Groups packets by source manufacturer inferred from known MAC address prefixes and limited device-name clues. Unknown, private, or randomized addresses may not be identifiable; these estimates can be incomplete.")
        self.apple_share_chart=VisualPanel("Apple share of mDNS packets","Packet counts by attribution confidence; percentage shown in subtitle","donut"); self.apple_share_chart.setMinimumHeight(260)
        self.apple_share_chart.setToolTip("Shows the fraction of packets attributed to Apple from known MAC prefixes or explicit device-name evidence. It is an estimate; unknown and randomized addresses are not counted as Apple. The percentage is shown in the subtitle.")
        self.active_status_chart.empty_message="No active discovery results yet. Open Bonjour discovery and browse/resolve service types to populate resolution health."
        self.active_types_chart.empty_message="No active browse results yet. Run Bonjour discovery to populate observed service types."
        self.expand_topology_btn=QPushButton("Expand Device activity ↗"); self.expand_topology_btn.setObjectName("secondary")
        self.expand_topology_btn.setToolTip("Open the Device activity chart in a larger, searchable window. This button expands only that graph.")
        graph_tools=QHBoxLayout(); graph_tools.addStretch(1); graph_tools.addWidget(self.expand_topology_btn); lay.addLayout(graph_tools)
        self.panel_widgets={
            "Live mDNS traffic":self.traffic,"Device activity":self.topology,"DNS record mix":self.records,
            "Top talkers":self.sources,"Multicast destinations":self.groups,
            "Packet size distribution":self.packet_sizes,"Most advertised DNS-SD names":self.dns_names,
            "Active discovery · service types":self.active_types_chart,"Resolution health":self.active_status_chart,
            "mDNS packets per second":self.packets_per_second,"mDNS by manufacturer":self.manufacturer_chart,
            "Apple share of mDNS packets":self.apple_share_chart,
        }
        # Put the four highest-value triage views first on a clean dashboard.
        self.panel_defaults=["Device activity", "DNS record mix", "Top talkers", "Live mDNS traffic",
            "Multicast destinations", "Packet size distribution", "Most advertised DNS-SD names",
            "Active discovery · service types", "Resolution health", "mDNS packets per second",
            "mDNS by manufacturer", "Apple share of mDNS packets"]
        self.layout_settings=QSettings("OpenAI", "mDNS Observatory")
        # Extra charts are available in Customize dashboard but remain off by default on clean installs.
        for optional_name in ("Packet size distribution", "Most advertised DNS-SD names", "Active discovery · service types", "Resolution health", "mDNS packets per second", "mDNS by manufacturer", "Apple share of mDNS packets"):
            key="dashboard/visible/"+optional_name
            if not self.layout_settings.contains(key): self.layout_settings.setValue(key, False)
        self.panel_order=self._read_panel_order()
        self.panel_cards={name:DashboardPanelCard(name,widget,self) for name,widget in self.panel_widgets.items()}
        self.panel_grid=QGridLayout(); self.panel_grid.setContentsMargins(0,0,0,0); self.panel_grid.setSpacing(12)
        lay.addLayout(self.panel_grid)
        self._rebuild_panel_grid()
        self.note=QLabel("Charts use a bounded recent packet window for responsiveness. Device and service totals reflect the analyzer inventory. Manufacturer and Apple-share charts combine known MAC OUIs with explicit device-name evidence; randomized or unknown MACs may remain unidentified.")
        self.note.setWordWrap(True); self.note.setStyleSheet("color:#8293a7;padding:4px;"); lay.addWidget(self.note)
        self.groups.drilldown_category="destination"
        self.sources.drilldown_category="source"
        self.topology.drilldown_category="source"
        self.traffic.drilldown_category="time_bucket"
        self.records.drilldown_category="record_type"
        self.active_types_chart.drilldown_category="active_type"
        self.active_status_chart.drilldown_category="resolution_state"
        self.packet_sizes.drilldown_category="packet_size"
        self.dns_names.drilldown_category="service_name"
        self.drilldown_targets={}
        for panel in self.panel_widgets.values(): panel.selected.connect(self.selected.emit)
        self.expand_topology_btn.clicked.connect(self.open_device_activity)
        self.customize_btn.clicked.connect(self.customize_layout)
        self._last_signature=None
        self.drilldown_value=""
        self.drilldown_category=""
        self.layout_widgets=self.panel_widgets
        self.restore_layout_visibility()
    def _read_panel_order(self):
        raw=self.layout_settings.value("dashboard/panel_order", "")
        try: saved=json.loads(str(raw))
        except Exception: saved=[]
        return [x for x in saved if x in self.panel_widgets] + [x for x in self.panel_widgets if x not in saved]
    def _read_columns(self):
        # Default to a three-column dashboard (three rows for the nine core panels).
        return max(1,min(3,self.layout_settings.value("dashboard/columns",3,type=int)))
    def _rebuild_panel_grid(self):
        while self.panel_grid.count():
            item=self.panel_grid.takeAt(0)
            if item.widget(): item.widget().setParent(None)
        columns=self._read_columns()
        for i,name in enumerate(self.panel_order):
            card=self.panel_cards[name]
            visible=self.layout_settings.value("dashboard/visible/"+name,True,type=bool)
            self.panel_widgets[name].setVisible(True)
            card.setVisible(visible)
            self.panel_grid.addWidget(card,i//columns,i%columns)
        for col in range(3): self.panel_grid.setColumnStretch(col,1 if col<columns else 0)
    def move_panel(self,source,target):
        if source not in self.panel_order or target not in self.panel_order: return
        self.panel_order.remove(source); self.panel_order.insert(self.panel_order.index(target),source)
        self.layout_settings.setValue("dashboard/panel_order",json.dumps(self.panel_order)); self.layout_settings.sync(); self._rebuild_panel_grid()
    def restore_layout_visibility(self):
        self._rebuild_panel_grid()
    def _named_layouts(self):
        raw=self.layout_settings.value("dashboard/named_layouts", "{}")
        try:
            data=json.loads(str(raw)); return data if isinstance(data,dict) else {}
        except Exception: return {}
    def _save_named_layouts(self, layouts):
        self.layout_settings.setValue("dashboard/named_layouts", json.dumps(layouts, sort_keys=True)); self.layout_settings.sync()
    def _apply_layout(self, layout):
        visibility=layout.get("visible",{})
        for name,widget in self.layout_widgets.items():
            self.layout_settings.setValue("dashboard/visible/"+name,bool(visibility.get(name,True)))
        order=layout.get("order",self.panel_defaults)
        self.panel_order=[x for x in order if x in self.panel_widgets]+[x for x in self.panel_widgets if x not in order]
        self.layout_settings.setValue("dashboard/panel_order",json.dumps(self.panel_order))
        self.layout_settings.setValue("dashboard/columns",max(1,min(3,int(layout.get("columns",3)))))
        self.layout_settings.sync(); self._rebuild_panel_grid()
    def customize_layout(self):
        dlg=QDialog(self); dlg.setWindowTitle("Customize dashboard layout"); dlg.setMinimumWidth(500)
        layout=QVBoxLayout(dlg)
        intro=QLabel("Drag the small grip (⠿) beside a panel title and drop it onto another panel to rearrange the dashboard. Choose which panels to show below. Optional graphs are listed separately."); intro.setWordWrap(True); layout.addWidget(intro)
        named_row=QHBoxLayout(); named_row.addWidget(QLabel("Saved layout")); presets=QComboBox(); named_row.addWidget(presets,1)
        layouts=self._named_layouts()
        def refresh_presets(select_name=None):
            presets.blockSignals(True); presets.clear(); presets.addItems(sorted(layouts.keys()))
            if select_name and select_name in layouts: presets.setCurrentText(select_name)
            presets.blockSignals(False)
        refresh_presets(); load_btn=QPushButton("Load"); save_btn=QPushButton("Save as…"); delete_btn=QPushButton("Delete")
        named_row.addWidget(load_btn); layout.addLayout(named_row)
        cols_row=QHBoxLayout(); cols_row.addWidget(QLabel("Grid columns")); columns=QComboBox(); columns.setObjectName("dashboardGridColumns"); columns.addItems(["1 column","2 columns","3 columns"]); columns.setCurrentIndex(self._read_columns()-1); columns.setMinimumWidth(150); columns.setStyleSheet("QComboBox { color:#f4f7fb; background:#263447; padding:7px 28px 7px 10px; min-height:22px; } QComboBox QAbstractItemView { color:#f4f7fb; background:#19222e; selection-background-color:#3b526d; }"); cols_row.addWidget(columns); cols_row.addStretch(1); layout.addLayout(cols_row)
        checks={}
        panel_scroll=QScrollArea(); panel_scroll.setObjectName("dashboardPanelChooserScroll")
        panel_scroll.setWidgetResizable(True); panel_scroll.setFrameShape(QFrame.Shape.StyledPanel)
        panel_scroll.setMinimumHeight(250); panel_scroll.setMaximumHeight(360)
        panel_body=QWidget(); panel_body_layout=QVBoxLayout(panel_body)
        panel_body_layout.setContentsMargins(12,8,12,8); panel_body_layout.setSpacing(7)
        core_names=["Device activity", "DNS record mix", "Top talkers", "Live mDNS traffic", "Multicast destinations"]
        optional_names=["Packet size distribution", "Most advertised DNS-SD names", "Active discovery · service types", "Resolution health", "mDNS packets per second", "mDNS by manufacturer", "Apple share of mDNS packets"]
        def add_panel_choice(name):
            cb=QCheckBox(name)
            cb.setChecked(self.layout_settings.value("dashboard/visible/"+name, name not in optional_names, type=bool))
            cb.setToolTip("Show or hide the “"+name+"” dashboard panel")
            panel_body_layout.addWidget(cb); checks[name]=cb
        core_heading=QLabel("CORE PANELS")
        core_heading.setStyleSheet("color:#ff9858;font-size:10px;font-weight:750;letter-spacing:1px;padding-top:3px")
        panel_body_layout.addWidget(core_heading)
        for name in core_names: add_panel_choice(name)
        optional_heading=QLabel("OPTIONAL GRAPHS · OFF BY DEFAULT")
        optional_heading.setStyleSheet("color:#ff9858;font-size:10px;font-weight:750;letter-spacing:1px;padding-top:10px")
        panel_body_layout.addWidget(optional_heading)
        for name in optional_names: add_panel_choice(name)
        panel_body_layout.addStretch(1); panel_scroll.setWidget(panel_body)
        layout.addWidget(QLabel("Panels to display")); layout.addWidget(panel_scroll)
        def load_selected():
            name=presets.currentText()
            if name not in layouts:return
            data=layouts[name]
            for key,cb in checks.items(): cb.setChecked(bool(data.get("visible",{}).get(key,True)))
            self.panel_order=[x for x in data.get("order",self.panel_defaults) if x in self.panel_widgets]+[x for x in self.panel_widgets if x not in data.get("order",self.panel_defaults)]
            columns.setCurrentIndex(max(0,min(2,int(data.get("columns",3))-1)))
        def save_named():
            name,ok=QInputDialog.getText(dlg,"Save dashboard layout","Layout name:",text=presets.currentText()); name=name.strip()
            if not ok or not name:return
            layouts[name]={"visible":{key:cb.isChecked() for key,cb in checks.items()},"order":list(self.panel_order),"columns":columns.currentIndex()+1}
            self._save_named_layouts(layouts); refresh_presets(name)
        def delete_named():
            name=presets.currentText()
            if name in layouts: del layouts[name]; self._save_named_layouts(layouts); refresh_presets()
        load_btn.clicked.connect(load_selected); save_btn.clicked.connect(save_named); delete_btn.clicked.connect(delete_named)
        actions=QHBoxLayout(); actions.addWidget(save_btn); actions.addWidget(delete_btn)
        def reset_defaults():
            self.panel_order=list(self.panel_defaults)
            for key,cb in checks.items(): cb.setChecked(key not in ("Packet size distribution", "Most advertised DNS-SD names", "Active discovery · service types", "Resolution health", "mDNS packets per second", "mDNS by manufacturer", "Apple share of mDNS packets"))
            columns.setCurrentIndex(2)
        reset=QPushButton("Reset defaults"); reset.setToolTip("Restore the default panel order, visibility, and three-column grid")
        reset.clicked.connect(reset_defaults); actions.addWidget(reset); layout.addLayout(actions)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Apply|QDialogButtonBox.StandardButton.Close)
        def apply():
            self._apply_layout({"visible":{key:cb.isChecked() for key,cb in checks.items()},"order":self.panel_order,"columns":columns.currentIndex()+1})
        buttons.button(QDialogButtonBox.StandardButton.Apply).clicked.connect(apply)
        buttons.rejected.connect(dlg.reject); buttons.button(QDialogButtonBox.StandardButton.Close).clicked.connect(dlg.accept); layout.addWidget(buttons); dlg.exec()
    def open_device_activity(self):
        dialog=DeviceActivityDialog(self.topology.data, self)
        dialog.showMaximized()
        dialog.exec()
    def set_drilldown(self,label,category,detail):
        self.drilldown_value=str(label)
        self.drilldown_category=str(category)
        self.drilldown_label.setText(detail)
        self.drilldown_banner.setVisible(True)
    def clear_drilldown(self):
        self.drilldown_value=""
        self.drilldown_category=""
        self.drilldown_banner.setVisible(False)
        self.filter_text.clear()
    def update_snapshot(self,s,active_results=None,discovery_events=None):
        active_results=list(active_results or [])
        discovery_events=list(discovery_events or [])
        active=[x for x in active_results if x.get("active",True) and x.get("event")!="remove"]
        resolved=[x for x in active if x.get("resolved") or x.get("status")=="Resolved"]
        errors=sum(1 for x in discovery_events if x.get("event") in ("error","resolve_error"))
        self.active_kpi_labels["active"].setText(f"{len(active):,}")
        self.active_kpi_labels["resolved"].setText(f"{len(resolved):,}")
        self.active_kpi_labels["types"].setText(f"{len({str(x.get('service_type','')).lower() for x in active if x.get('service_type')}):,}")
        self.active_kpi_labels["errors"].setText(f"{errors:,}")
        type_counts=Counter(str(x.get("service_type") or "Unknown") for x in active)
        self.active_types_chart.set_data(type_counts.most_common(8))
        status_counts=Counter("Resolved" if (x.get("resolved") or x.get("status")=="Resolved") else ("Error" if "error" in str(x.get("status","")).lower() else "Resolving") for x in active)
        self.active_status_chart.set_data(status_counts.most_common(6))
        packets=s.get("packets",[]); query=self.filter_text.text().strip().lower(); range_text=self.time_range.currentText()
        parsed=[]
        for pkt in packets:
            try: dt=datetime.fromisoformat(str(pkt.get("time","")))
            except Exception: dt=None
            parsed.append((pkt,dt))
        valid=[dt for _,dt in parsed if dt is not None]; latest=max(valid) if valid else None
        minutes={"Last 5 minutes":5,"Last 15 minutes":15,"Last hour":60}.get(range_text); filtered=[]
        for pkt,dt in parsed:
            if minutes and latest and dt and (latest-dt).total_seconds()>minutes*60: continue
            hay=" ".join([str(pkt.get(k,"")) for k in ("source","destination","mac","vlan","direction","family")] + [str(x) for x in pkt.get("questions",[])] + [str(x) for x in pkt.get("records",[])]).lower()
            if query and query not in hay: continue
            filtered.append(pkt)
        buckets=Counter()
        for pkt in filtered:
            try: key=datetime.fromisoformat(str(pkt.get("time",""))).strftime("%H:%M")
            except Exception: key="time?"
            buckets[key]+=1
        self.traffic.set_data(list(buckets.items())[-60:])
        top=Counter(pkt.get("source") or "unknown" for pkt in filtered)
        ip_to_host={}
        for device in s.get("devices",[]):
            ip=str(device.get("ip") or "")
            names=device.get("hostnames") or []
            if ip and names:
                ip_to_host[ip]=str(sorted(names,key=lambda x:(len(str(x)),str(x).casefold()))[0])
        self.drilldown_targets={}
        def chart_label(ip):
            host=ip_to_host.get(str(ip))
            label=f"{host} ({ip})" if host else str(ip)
            self.drilldown_targets[label]=str(ip)
            return label
        self.topology.set_data([(chart_label(ip),count,"device") for ip,count in top.most_common(12)])
        self.groups.set_data(Counter(pkt.get("destination") or "unknown" for pkt in filtered).most_common(10))
        rec=Counter()
        for pkt in filtered:
            for r in pkt.get("records",[]): rec[str(r.get("type","Other"))]+=1
            for q in pkt.get("questions",[]): rec["Query "+str(q.get("type","Other"))]+=1
        self.records.set_data(rec.most_common(8)); self.sources.set_data([(chart_label(ip),count) for ip,count in top.most_common(10)])
        size_bins=Counter()
        for pkt in filtered:
            try: n=int(pkt.get("length",pkt.get("bytes",0)) or 0)
            except (TypeError,ValueError): n=0
            if n <= 128: bucket="0–128 B"
            elif n <= 256: bucket="129–256 B"
            elif n <= 512: bucket="257–512 B"
            elif n <= 1024: bucket="513–1024 B"
            else: bucket=">1024 B"
            size_bins[bucket]+=1
        order=["0–128 B","129–256 B","257–512 B","513–1024 B",">1024 B"]
        self.packet_sizes.set_data([(b,size_bins[b]) for b in order if size_bins[b]])
        # Per-second rate based on the visible packet window and selected source filter.
        pps=Counter()
        manufacturer_packets=Counter()
        manufacturer_devices={}
        apple_packets=0
        apple_device_keys=set()
        device_mac_by_ip={str(d.get("ip") or ""): str(d.get("mac") or "") for d in s.get("devices",[]) if d.get("ip")}
        for pkt in filtered:
            try:
                dt=datetime.fromisoformat(str(pkt.get("time", ""))).replace(microsecond=0)
                second_key=dt.timestamp()
            except Exception:
                second_key=None
            if second_key is not None:
                pps[second_key] += 1
            src_ip=str(pkt.get("source") or "")
            mac=str(pkt.get("mac") or device_mac_by_ip.get(src_ip) or "")
            vendor=packet_manufacturer(mac, src_ip, ip_to_host,
                                       pkt.get("records", ()), pkt.get("questions", ()))
            manufacturer_packets[vendor] += 1
            device_key=mac.lower() if mac else src_ip
            if device_key:
                manufacturer_devices.setdefault(vendor,set()).add(device_key)
            if vendor in ("Apple", "Apple (hostname inferred)"):
                apple_packets += 1
                if device_key: apple_device_keys.add(device_key)
        pps_rows=[]
        for stamp,count in sorted(pps.items())[-60:]:
            pps_rows.append((datetime.fromtimestamp(stamp).strftime("%H:%M:%S"),count))
        self.packets_per_second.set_data(pps_rows)
        self.manufacturer_chart.set_data(manufacturer_packets.most_common(10))
        # Keep Apple-share donut in packet-count units, matching the manufacturer chart.
        # The donut renderer computes slice percentages from these counts; its center now
        # represents the actual number of packets rather than a misleading 100 percent.
        if filtered:
            apple_pct=100.0*apple_packets/len(filtered)
            apple_devices=len(apple_device_keys)
            known_device_count=sum(len(v) for k,v in manufacturer_devices.items() if k not in ("Other / unknown vendor", "Unknown / unavailable", "Private / randomized MAC"))
            self.apple_share_chart.set_data([("Apple", apple_packets), ("Other identified", max(0, sum(v for k,v in manufacturer_packets.items() if k not in ("Apple", "Apple (hostname inferred)", "Other / unknown vendor", "Unknown / unavailable", "Private / randomized MAC")))), ("Private / randomized MAC", manufacturer_packets.get("Private / randomized MAC", 0)), ("Other / unknown", manufacturer_packets.get("Other / unknown vendor", 0)+manufacturer_packets.get("Unknown / unavailable", 0))])
            self.apple_share_chart.subtitle=f"{apple_pct:.1f}% of {len(filtered):,} packets attributed to Apple · {apple_devices:,} distinct Apple source identifiers; unknowns are not counted as Apple"
        else:
            self.apple_share_chart.set_data([])
            self.apple_share_chart.empty_message="No packets in the selected window. Apple share is unavailable, not 0%."
        service_names=Counter()
        for pkt in filtered:
            for rr in pkt.get("records",[]):
                typ=str(rr.get("type","")).upper(); name=str(rr.get("name") or rr.get("owner") or rr.get("value") or "")
                if typ=="PTR" and name: service_names[name]+=1
        self.dns_names.set_data(service_names.most_common(8))
        window_note=f"latest {len(packets):,} packets" if len(packets)>=self.CHART_WINDOW else f"{len(packets):,} retained packets"
        self.summary.setText(f"Showing {len(filtered):,} of {len(packets):,} chart-window packets · {len(top)} sources · source filter applies to passive evidence only")
        self.note.setText(f"Charts summarize {window_note} for responsiveness. Headline device and service totals reflect the analyzer inventory; chart filters apply to the plotted packet window.")


class ConversationMap(QWidget):
    """Interactive left-to-right map of observed source → destination flows."""
    flow_selected = Signal(str, str)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows=[]; self.edge_hits=[]; self.source_nodes=[]; self.dest_nodes=[]; self.hostname_map={}
        self.setMinimumHeight(390)
        self.setStyleSheet("background:#141c26;border:1px solid #344255;border-radius:12px;")
    def set_rows(self, rows, hostname_map=None):
        self.rows=list(rows or [])
        self.hostname_map=dict(hostname_map or {})
        self.update()
    def display_endpoint(self, value):
        value=str(value or "")
        hostname=self.hostname_map.get(value)
        return f"{hostname} ({value})" if hostname and hostname != "—" else value
    def mousePressEvent(self, event):
        pos=event.position().toPoint()
        best=None; best_distance=10**9
        px,py=pos.x(),pos.y()
        for points,source,dest in self.edge_hits:
            for (x1,y1),(x2,y2) in zip(points,points[1:]):
                dx=x2-x1; dy=y2-y1
                length2=dx*dx+dy*dy
                t=0 if not length2 else max(0,min(1,((px-x1)*dx+(py-y1)*dy)/length2))
                distance=((px-(x1+t*dx))**2+(py-(y1+t*dy))**2)**0.5
                if distance<best_distance: best_distance=distance; best=(source,dest)
        if best and best_distance<=10:
            self.flow_selected.emit(best[0],best[1]); return
        super().mousePressEvent(event)
    def paintEvent(self,event):
        from PySide6.QtCore import QRect, QPointF
        p=QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(),QColor('#141c26')); self.edge_hits=[]
        p.setPen(QColor('#eef3fa')); p.setFont(QFont('SF Pro Text',13,QFont.Weight.DemiBold)); p.drawText(18,27,'Conversation map')
        p.setPen(QColor('#94a4b7')); p.setFont(QFont('SF Pro Text',9)); p.drawText(18,47,'Select a connection to inspect matching captured packets · line width reflects observed packet count')
        area=self.rect().adjusted(18,62,-18,-18)
        if not self.rows:
            p.setPen(QColor('#94a4b7')); p.drawText(area,Qt.AlignmentFlag.AlignCenter,'Import a capture or start monitoring to map observed conversations.'); p.end(); return
        rows=sorted(self.rows,key=lambda r:int(r[3]),reverse=True)[:18]
        src_counts=Counter(); dst_counts=Counter()
        for r in rows: src_counts[str(r[0])]+=int(r[3]); dst_counts[str(r[1])]+=int(r[3])
        sources=[x for x,_ in src_counts.most_common(8)]; dests=[x for x,_ in dst_counts.most_common(8)]
        left_x=area.left()+8; right_x=area.right()-8; node_w=min(190,max(130,int(area.width()*.24)))
        sx=left_x+node_w; dx=right_x-node_w
        sh=max(30,min(44,int((area.height()-8)/max(1,len(sources))))); dh=max(30,min(44,int((area.height()-8)/max(1,len(dests)))))
        source_y={v:int(area.top()+i*(area.height()/max(1,len(sources)))+area.height()/max(1,len(sources))/2) for i,v in enumerate(sources)}
        dest_y={v:int(area.top()+i*(area.height()/max(1,len(dests)))+area.height()/max(1,len(dests))/2) for i,v in enumerate(dests)}
        max_packets=max([int(r[3]) for r in rows]+[1])
        # Draw connections first so the nodes remain readable.
        for r in rows:
            src,dst=str(r[0]),str(r[1])
            if src not in source_y or dst not in dest_y: continue
            y1,y2=source_y[src],dest_y[dst]; count=int(r[3]); width=1.2+5.5*(count/max_packets)
            multicast=str(r[2]).lower().startswith('multicast')
            color=QColor('#45b8a8' if multicast else '#ff914d'); color.setAlpha(65+int(150*count/max_packets))
            pen=QPen(color,width); pen.setCapStyle(Qt.PenCapStyle.RoundCap); p.setPen(pen)
            path=QPainterPath(); path.moveTo(sx,y1); c1=(sx+(dx-sx)*.42,y1); c2=(sx+(dx-sx)*.58,y2); path.cubicTo(c1[0],c1[1],c2[0],c2[1],dx,y2); p.drawPath(path)
            points=[]
            for step in range(21):
                t=step/20; u=1-t
                points.append((int(u*u*u*sx+3*u*u*t*c1[0]+3*u*t*t*c2[0]+t*t*t*dx),int(u*u*u*y1+3*u*u*t*c1[1]+3*u*t*t*c2[1]+t*t*t*y2)))
            self.edge_hits.append((points,src,dst))
        for vals,x,y_map,color,title in [(sources,left_x,source_y,QColor('#25384b'),'SOURCES'),(dests,right_x-node_w,y_map if False else dest_y,QColor('#263b3a'),'DESTINATIONS / GROUPS')]:
            p.setPen(QColor('#ffb17f')); p.setFont(QFont('SF Pro Text',8,QFont.Weight.Bold)); p.drawText(x,area.top()-4,title)
            for label in vals:
                cy=y_map[label]; rect=QRect(x,cy-sh//2,node_w,sh)
                p.setPen(QPen(QColor('#40536a'),1)); p.setBrush(color); p.drawRoundedRect(rect,7,7)
                p.setPen(QColor('#f0f4f8')); p.setFont(QFont('SF Pro Text',9,QFont.Weight.DemiBold))
                display=self.display_endpoint(label)
                metrics=QFontMetrics(p.font()); text=metrics.elidedText(display,Qt.TextElideMode.ElideRight,rect.width()-16)
                p.drawText(rect.adjusted(9,0,-7,0),Qt.AlignmentFlag.AlignVCenter|Qt.AlignmentFlag.AlignLeft,text)
        p.setPen(QColor('#8fa1b5')); p.setFont(QFont('SF Pro Text',8)); p.drawText(area.left(),area.bottom()+2,f'{len(rows)} strongest observed flows shown · multicast does not prove individual receiver delivery')
        p.end()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle(APP_NAME + " " + APP_VERSION); self.setWindowIcon(QIcon(app_icon_path())); self.resize(1360,860); self.an=Analyzer(); self.bus=Bus(); self.bus.changed.connect(self.refresh); self.bus.status.connect(self.set_status); self.bus.discovery_event.connect(self.handle_discovery_event); self.bus.capture_finished.connect(self.capture_finished); self.bus.discovery_finished.connect(self.discovery_finished); self.bus.catalog_update_finished.connect(self.on_community_catalog_fetched); self.capture=None; self.browser=None; self.active_results={}; self.discovery_events=[]; self._comparison_cache_key=None; self._comparison_data=[]
        self.setStyleSheet("""
        QMainWindow, QWidget { background:#10151d; color:#e9eef5; font-size:13px; }
        QLabel#hero {font-size:25px;font-weight:700;color:#f4f7fb;} QLabel#sub {color:#9eacbd;font-size:12px;}
        QFrame#metric {background:#19222e;border:1px solid #293647;border-radius:12px;} QLabel#metricValue {font-size:25px;font-weight:700;color:#ff8b42;} QLabel#metricLabel {color:#aab7c7;font-size:11px;}
        QPushButton {background:#f5823a;color:#15191f;border:0;border-radius:7px;padding:9px 13px;font-weight:650;} QPushButton:hover {background:#ff9a5c;} QPushButton:disabled {background:#454d58;color:#a6adb6;}
        QPushButton#secondary {background:#273445;color:#e9eef5;} QPushButton#secondary:hover {background:#34465b;}
        QTabWidget::pane {border:1px solid #2b394b;border-radius:12px;top:-1px;background:#111923;} QTabBar::tab {background:#182230;color:#9eacbd;padding:12px 19px;margin-right:4px;border-top-left-radius:8px;border-top-right-radius:8px;font-weight:600;} QTabBar::tab:selected {background:#263548;color:#ffffff;border-bottom:3px solid #ff8b42;} QTabBar::tab:hover:!selected {background:#202d3d;color:#edf2f7;}
        QTableWidget {background:#121a24;alternate-background-color:#17212d;gridline-color:#253345;border:1px solid #2b394b;border-radius:10px;selection-background-color:#3a3029;selection-color:#fff;outline:0;padding:4px;} QTableWidget::item {padding:7px 9px;border-bottom:1px solid #202c3a;} QTableWidget::item:selected {background:#3b3028;color:#ffffff;} QHeaderView::section {background:#202d3d;color:#d1dbe7;border:0;border-right:1px solid #2b394b;border-bottom:1px solid #34465b;padding:11px 10px;font-weight:700;} QHeaderView::section:hover {background:#2a3b50;color:#ffb17f;} QLineEdit,QComboBox {background:#19222e;border:1px solid #344255;border-radius:7px;padding:9px;color:#edf2f7;} QTextEdit {background:#141c26;border:1px solid #293647;border-radius:10px;padding:10px;} QScrollBar:vertical {background:#141c26;width:12px;margin:2px;} QScrollBar::handle:vertical {background:#34465b;border-radius:5px;min-height:24px;} QScrollBar:horizontal {background:#141c26;height:12px;margin:2px;} QScrollBar::handle:horizontal {background:#52677f;border-radius:5px;min-width:28px;} QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {height:0;} QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal {width:0;}
        """)
        # Keep the overall application viewport vertical-only. Wide tables and
        # chart widgets may use their own internal horizontal scrollbars, but the
        # whole page should never slide sideways.
        app_scroll = QScrollArea()
        app_scroll.setObjectName("applicationScrollArea")
        app_scroll.setWidgetResizable(True)
        app_scroll.setFrameShape(QFrame.Shape.NoFrame)
        app_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        app_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setCentralWidget(app_scroll)
        root=QWidget()
        root.setObjectName("applicationSurface")
        root.setMinimumWidth(0)
        root.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        app_scroll.setWidget(root)
        layout=QVBoxLayout(root); layout.setContentsMargins(22,18,22,16); layout.setSpacing(13)
        head=QHBoxLayout(); left=QVBoxLayout(); title=QLabel("mDNS Observatory"); title.setObjectName("hero"); subtitle=QLabel("Passive mDNS analysis · active Bonjour discovery on macOS"); subtitle.setObjectName("sub"); left.addWidget(title); left.addWidget(subtitle); head.addLayout(left); head.addStretch()
        self.iface=QComboBox(); self.iface.setMinimumWidth(190); self.populate_interfaces(); head.addWidget(QLabel("Interface")); head.addWidget(self.iface)
        head.addWidget(QLabel("Traffic source"))
        self.source_filter=QComboBox(); self.source_filter.setObjectName("trafficSourceFilter")
        self.source_filter.addItem("All sources", "all")
        self.source_filter.addItem("ERSPAN tunnel", "erspan")
        self.source_filter.addItem("Local traffic", "local")
        self.source_filter.setToolTip("Filters passive captured/imported packet evidence and its derived views only. Active Bonjour discovery is a separate OS DNS-SD operation and is not filtered by this selector. Capture continues in the background.")
        self.source_filter.currentIndexChanged.connect(self.on_source_filter_changed)
        head.addWidget(self.source_filter)
        refresh_iface_btn=QPushButton("↻"); refresh_iface_btn.setObjectName("secondary"); refresh_iface_btn.setToolTip("Refresh network interfaces"); refresh_iface_btn.clicked.connect(self.refresh_interfaces); head.addWidget(refresh_iface_btn)
        self.start_btn=QPushButton("Start capture"); self.start_btn.clicked.connect(self.toggle_capture); head.addWidget(self.start_btn)
        load_btn=QPushButton("Import PCAP"); load_btn.setObjectName("secondary"); load_btn.clicked.connect(self.import_pcap); head.addWidget(load_btn)
        save_btn=QPushButton("Save session"); save_btn.setObjectName("secondary"); save_btn.clicked.connect(self.save_session); head.addWidget(save_btn)
        open_btn=QPushButton("Open session"); open_btn.setObjectName("secondary"); open_btn.clicked.connect(self.open_session); head.addWidget(open_btn)
        report_btn=QPushButton("Export report"); report_btn.setObjectName("secondary"); report_btn.clicked.connect(self.export_report); head.addWidget(report_btn); layout.addLayout(head)
        metrics=QHBoxLayout(); self.metric_labels={};
        for key,label in [("packets","mDNS packets"),("devices","Source devices"),("services","Service instances"),("groups","Destinations")]:
            frame=QFrame(); frame.setObjectName("metric"); fl=QVBoxLayout(frame); fl.setContentsMargins(16,12,16,12); v=QLabel("0"); v.setObjectName("metricValue"); l=QLabel(label); l.setObjectName("metricLabel"); fl.addWidget(v); fl.addWidget(l); metrics.addWidget(frame); self.metric_labels[key]=v
        layout.addLayout(metrics)
        filter_row=QHBoxLayout(); filter_row.addWidget(QLabel("Workspace")); self.workspace_picker=QComboBox(); self.workspace_picker.setMinimumWidth(250); self.workspace_picker.setToolTip("Choose a workspace; navigation is in this menu to keep the window uncluttered"); filter_row.addWidget(self.workspace_picker); filter_row.addSpacing(12); filter_row.addWidget(QLabel("Filter current table"))
        self.table_filter=QLineEdit(); self.table_filter.setPlaceholderText("Type to filter visible rows…"); self.table_filter.setClearButtonEnabled(True); filter_row.addWidget(self.table_filter,1)
        filter_hint=QLabel("Saved per view"); filter_hint.setObjectName("sub"); filter_row.addWidget(filter_hint); layout.addLayout(filter_row)
        self.drilldown_bar=QFrame(); self.drilldown_bar.setObjectName("metric")
        drilldown_layout=QHBoxLayout(self.drilldown_bar); drilldown_layout.setContentsMargins(12,7,12,7)
        self.drilldown_status=QLabel(); self.drilldown_status.setWordWrap(True); self.drilldown_status.setStyleSheet("color:#c7d3e2;")
        self.drilldown_back_btn=QPushButton("Back"); self.drilldown_back_btn.setObjectName("secondary"); self.drilldown_back_btn.setToolTip("Undo the most recent drill-down and return to its previous filter or view."); self.drilldown_back_btn.clicked.connect(self.back_drilldown)
        self.drilldown_clear_btn=QPushButton("Clear drill-downs"); self.drilldown_clear_btn.setObjectName("secondary"); self.drilldown_clear_btn.setToolTip("Remove all chart and workspace drill-down filters."); self.drilldown_clear_btn.clicked.connect(self.clear_all_workspace_drilldowns)
        drilldown_layout.addWidget(self.drilldown_status,1); drilldown_layout.addWidget(self.drilldown_back_btn); drilldown_layout.addWidget(self.drilldown_clear_btn)
        self.drilldown_bar.hide(); layout.addWidget(self.drilldown_bar)
        self.tabs=QTabWidget()
        self.tabs.setMinimumWidth(0)
        self.tabs.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Expanding)
        layout.addWidget(self.tabs,1)
        self.settings=QSettings("OpenAI", "mDNS Observatory")
        saved_source = self.settings.value("trafficSourceFilter", "all")
        saved_index = self.source_filter.findData(saved_source)
        if saved_index >= 0:
            self.source_filter.blockSignals(True)
            self.source_filter.setCurrentIndex(saved_index)
            self.source_filter.blockSignals(False)
        self._table_filter_values={}
        self.table_filter.textChanged.connect(self.apply_current_table_filter)
        self.tabs.currentChanged.connect(self.restore_current_table_filter)
        self.dashboard=Dashboard(); self.dashboard.selected.connect(self.dashboard_drilldown); self.dashboard.clear_drilldown_btn.clicked.disconnect(); self.dashboard.clear_drilldown_btn.clicked.connect(self.clear_dashboard_drilldown); self.dashboard.view_packets_btn.clicked.connect(lambda: self.tabs.setCurrentWidget(self.packet_table)); self.dashboard.discovery_btn.clicked.connect(self.toggle_browse); self.dashboard.time_range.currentTextChanged.connect(self.refresh); self.dashboard.filter_text.textChanged.connect(self.schedule_refresh); self.tabs.addTab(self.dashboard,"Visual dashboard")
        self.tabs.currentChanged.connect(self.on_tab_changed)
        self.packet_table=self.make_table(["Time","Type","Capture source","Source","Destination","VLAN","Questions / records","Bytes","Source hostname","Destination hostname"]); 
        # A mirror destination is an ordinary capture interface from the app's perspective.
        # The user configures the ICX 8200 mirror session externally; this app only listens.
        self.tabs.addTab(self.packet_table,"Live traffic / Mirror capture")
        devices_tab=QWidget(); devices_layout=QVBoxLayout(devices_tab); devices_layout.setContentsMargins(10,10,10,10); devices_layout.setSpacing(10)
        device_charts=QHBoxLayout(); self.device_top_sources=VisualPanel("Most active devices","Ranked by observed mDNS packets","bars"); self.device_vlan_chart=VisualPanel("Observed VLAN distribution","Evidence from visible 802.1Q tags","donut")
        self.device_top_sources.setMinimumHeight(245); self.device_vlan_chart.setMinimumHeight(245); device_charts.addWidget(self.device_top_sources,3); device_charts.addWidget(self.device_vlan_chart,2); devices_layout.addLayout(device_charts); self.device_top_sources.selected.connect(self.device_chart_drilldown)
        device_actions=QHBoxLayout(); device_actions.addWidget(QLabel("Device health and activity")); device_actions.addStretch()
        self.device_health=QLabel("No device selected"); self.device_health.setObjectName("sub"); device_actions.addWidget(self.device_health)
        self.device_inspect_btn=QPushButton("View device services & explanation"); self.device_inspect_btn.setObjectName("secondary"); self.device_inspect_btn.setToolTip("Select a device row to list services it advertised or targeted, with plain-language explanations and capture evidence."); self.device_inspect_btn.clicked.connect(self.inspect_selected_device); device_actions.addWidget(self.device_inspect_btn)
        self.device_chains_btn=QPushButton("View service chains"); self.device_chains_btn.setObjectName("secondary"); self.device_chains_btn.clicked.connect(self.selected_device_chains); device_actions.addWidget(self.device_chains_btn)
        self.device_packets_btn=QPushButton("View packet evidence"); self.device_packets_btn.setObjectName("secondary"); self.device_packets_btn.clicked.connect(self.selected_device_packets); device_actions.addWidget(self.device_packets_btn)
        devices_layout.addLayout(device_actions)
        self.device_table=self.make_table(["Hostname / IP address","MAC address","VLAN","Packets","Queries","Responses","Other hostnames","Services","Last seen"]); devices_layout.addWidget(self.device_table,1); self.tabs.addTab(devices_tab,"Devices")
        self.device_table.cellDoubleClicked.connect(self.inspect_device); self.device_table.itemSelectionChanged.connect(self.update_device_health)
        service_tab=QWidget(); service_layout=QVBoxLayout(service_tab); service_layout.setContentsMargins(10,10,10,10); service_layout.setSpacing(10)
        service_kpis=QHBoxLayout(); self.service_kpi_labels={}
        for key,label in [("instances","Instances"),("types","Service types"),("resolved","With target"),("issues","Incomplete / conflicts")]:
            frame=QFrame(); frame.setObjectName("metric"); fl=QVBoxLayout(frame); fl.setContentsMargins(14,10,14,10)
            val=QLabel("0"); val.setObjectName("metricValue"); cap=QLabel(label); cap.setObjectName("metricLabel"); fl.addWidget(val); fl.addWidget(cap); service_kpis.addWidget(frame); self.service_kpi_labels[key]=val
        service_layout.addLayout(service_kpis)
        service_charts=QHBoxLayout(); self.service_type_chart=VisualPanel("Most common service types","Click a type to filter the service inventory","bars"); self.service_type_chart.setMinimumHeight(300)
        self.service_type_chart.setToolTip("Ranks DNS-SD service types seen in passive PTR records. A type such as _ipp._tcp names a protocol category, not a specific device. Click a bar to filter the Services inventory.")
        self.service_health_chart=VisualPanel("Service-chain health","Observed evidence completeness · not reachability","donut"); self.service_health_chart.setMinimumHeight(300)
        self.service_health_chart.setToolTip("Summarizes how much of each advertised service chain was observed (PTR, SRV, TXT, and address records). Complete evidence does not prove reachability; missing evidence can reflect a partial capture.")
        service_charts.addWidget(self.service_type_chart,3); service_charts.addWidget(self.service_health_chart,2); service_layout.addLayout(service_charts)
        self.service_type_chart.selected.connect(self.service_chart_drilldown); self.service_health_chart.selected.connect(self.service_health_drilldown)
        service_actions=QHBoxLayout(); service_actions.addWidget(QLabel("Service inventory")); service_actions.addStretch(); self.service_explain_btn=QPushButton("Explain selected service"); self.service_explain_btn.setObjectName("secondary"); self.service_explain_btn.setToolTip("Select a service row to see its plain-language purpose and the packet evidence observed for it."); self.service_explain_btn.clicked.connect(self.explain_selected_service); service_actions.addWidget(self.service_explain_btn); self.service_chain_btn=QPushButton("Open selected service chain"); self.service_chain_btn.setObjectName("secondary"); self.service_chain_btn.clicked.connect(self.selected_service_chain); service_actions.addWidget(self.service_chain_btn); self.service_packets_btn=QPushButton("Show packet evidence"); self.service_packets_btn.setObjectName("secondary"); self.service_packets_btn.clicked.connect(self.selected_service_packets); service_actions.addWidget(self.service_packets_btn); service_layout.addLayout(service_actions)
        self.service_table=self.make_table(["Service instance / PTR target","Service type","Target","Port","TXT data","Sources","Last seen","Source hostnames"]); service_layout.addWidget(self.service_table,1); self.tabs.addTab(service_tab,"Services")
        self.service_table.cellDoubleClicked.connect(self.service_row_drilldown)
        self.service_table.itemSelectionChanged.connect(self.update_service_explanation_action)
        self.group_table=self.make_table(["Destination group","Packets","Share"]); self.tabs.addTab(self.group_table,"Multicast groups")
        findings_tab=QWidget(); findings_layout=QVBoxLayout(findings_tab); findings_layout.setContentsMargins(10,10,10,10)
        findings_actions=QHBoxLayout(); findings_actions.addWidget(QLabel("Capture diagnostics and support tools")); findings_actions.addStretch()
        diagnostics_btn=QPushButton("Runtime diagnostics"); diagnostics_btn.setObjectName("secondary"); diagnostics_btn.clicked.connect(self.show_runtime_diagnostics); findings_actions.addWidget(diagnostics_btn)
        support_btn=QPushButton("Export support bundle"); support_btn.setObjectName("secondary"); support_btn.setToolTip("Export diagnostics without raw packet payloads"); support_btn.clicked.connect(self.export_support_bundle); findings_actions.addWidget(support_btn)
        clear_filters_btn=QPushButton("Clear workspace drill-downs"); clear_filters_btn.setObjectName("secondary"); clear_filters_btn.clicked.connect(self.clear_all_workspace_drilldowns); findings_actions.addWidget(clear_filters_btn)
        findings_layout.addLayout(findings_actions)
        self.report_text=QTextEdit(); self.report_text.setReadOnly(True); findings_layout.addWidget(self.report_text,1); self.tabs.addTab(findings_tab,"Findings")
        # Active Bonjour browsing uses Apple's native DNS-SD daemon (libdns_sd).
        active=QWidget(); al=QVBoxLayout(active); al.setContentsMargins(10,10,10,10)
        controls=QHBoxLayout(); self.discovery_types=QLineEdit(); self.discovery_types.setPlaceholderText("Optional service types, comma-separated (blank = common types)"); self.discovery_types.setToolTip("Examples: _airplay._tcp, _ipp._tcp, _googlecast._tcp")
        controls.addWidget(self.discovery_types,1); self.browse_btn=QPushButton("Start Bonjour discovery"); self.browse_btn.clicked.connect(self.toggle_browse); controls.addWidget(self.browse_btn)
        if sys.platform != "darwin":
            self.browse_btn.setText("Bonjour discovery (macOS only)")
            self.browse_btn.setToolTip("Active Bonjour browsing currently uses Apple's native DNS-SD library and is available on macOS only.")
            self.browse_btn.setEnabled(False)
        clear_disc=QPushButton("Clear discoveries"); clear_disc.setObjectName("secondary"); clear_disc.clicked.connect(self.clear_discoveries); controls.addWidget(clear_disc); al.addLayout(controls)
        note=QLabel("Uses Apple's DNS-SD browsing and resolution APIs. Active browse results are independent of the passive Traffic Source filter; the filter only affects captured/imported packets and their derived analysis. Packet counts remain passive capture only."); note.setObjectName("sub"); al.addWidget(note)
        self.active_table=self.make_table(["Service instance","Service type","Host target","Port","TXT metadata","Interface","Status","Last seen"]); al.addWidget(self.active_table,1); self.tabs.addTab(active,"Active discovery")
        compare=QWidget(); cl=QVBoxLayout(compare); cl.setContentsMargins(10,10,10,10)
        compare_note=QLabel("Correlates active Bonjour results with services seen in passive capture/import. A mismatch is a visibility difference, not proof of a network fault."); compare_note.setObjectName("sub"); cl.addWidget(compare_note)
        self.compare_table=self.make_table(["Service instance","Passive seen","Active browse","Target","Port","Interpretation"]); cl.addWidget(self.compare_table,1); self.comparison_tab=compare; self.tabs.addTab(compare,"Discovery comparison")
        # Human-friendly service catalog and RUCKUS One planning helper.
        catalog=QWidget(); cal=QVBoxLayout(catalog); cal.setContentsMargins(10,10,10,10)
        cat_note=QLabel("Friendly names mapped to DNS-SD types. RUCKUS One predefined availability can vary by release; verify the rule selector before deployment."); cat_note.setObjectName("sub"); cal.addWidget(cat_note)
        cat_controls=QHBoxLayout(); self.catalog_search=QLineEdit(); self.catalog_search.setPlaceholderText("Filter by name, type, category, or use…"); self.catalog_search.textChanged.connect(self.refresh_catalog); cat_controls.addWidget(self.catalog_search,1)
        self.catalog_category=QComboBox(); self.catalog_category.addItem("All categories")
        self.catalog_update_btn=QPushButton("Update community catalog"); self.catalog_update_btn.setObjectName("secondary"); self.catalog_update_btn.setToolTip("Check the community-maintained mDNS service reference on GitHub. Downloaded data is validated and shown for confirmation before replacing the saved community entries."); self.catalog_update_btn.clicked.connect(self.update_community_catalog)
        self.catalog_export_btn=QPushButton("Export R1 rule planner CSV"); self.catalog_export_btn.setObjectName("secondary"); self.catalog_export_btn.clicked.connect(self.export_rule_planner)
        cat_controls.addWidget(self.catalog_category); cat_controls.addWidget(self.catalog_update_btn); cat_controls.addWidget(self.catalog_export_btn); cal.addLayout(cat_controls)
        self.catalog_update_status=QLabel("Loading bundled community catalog…"); self.catalog_update_status.setObjectName("sub"); self.catalog_update_status.setWordWrap(True); cal.addWidget(self.catalog_update_status)
        self.catalog_table=self.make_table(["Friendly name","DNS-SD type","Transport","Category","Purpose","RUCKUS One guidance"]); cal.addWidget(self.catalog_table,1); self.tabs.addTab(catalog,"Service catalog / R1 planner")
        self.catalog_data=self.load_service_catalog()
        self.refresh_catalog_update_status()
        # VLAN visibility and forwarding-rule analyzer (read-only; no R1 changes).
        vlan_tab=QWidget(); vl=QVBoxLayout(vlan_tab); vl.setContentsMargins(10,10,10,10)
        vlan_note=QLabel("Compare observed mDNS advertisements/queries with intended RUCKUS One forwarding rules. Capture VLANs are only known when tags or capture metadata expose them; Unknown is not guessed. This is an analysis aid, not proof of proxy behavior."); vlan_note.setObjectName("sub"); vlan_note.setWordWrap(True); vl.addWidget(vlan_note)
        rule_controls=QHBoxLayout(); self.rule_service=QComboBox(); self.rule_service.setEditable(True); self.rule_service.setMinimumWidth(260)
        for item in self.catalog_data: self.rule_service.addItem(f"{item.get('name','')} — {item.get('type','')}", item.get('type',''))
        self.rule_from=QLineEdit(); self.rule_from.setPlaceholderText("From VLAN (service source)"); self.rule_from.setMaximumWidth(180)
        self.rule_to=QLineEdit(); self.rule_to.setPlaceholderText("To VLAN (requesting clients)"); self.rule_to.setMaximumWidth(180)
        self.rule_add=QPushButton("Add intended rule"); self.rule_add.clicked.connect(self.add_intended_rule)
        rule_controls.addWidget(self.rule_service,2); rule_controls.addWidget(self.rule_from); rule_controls.addWidget(self.rule_to); rule_controls.addWidget(self.rule_add); vl.addLayout(rule_controls)
        rule_actions=QHBoxLayout(); self.rule_analyze_btn=QPushButton("Analyze observed traffic vs rules"); self.rule_analyze_btn.clicked.connect(self.analyze_vlan_rules); rule_actions.addWidget(self.rule_analyze_btn)
        self.rule_export_btn=QPushButton("Export analysis CSV"); self.rule_export_btn.setObjectName("secondary"); self.rule_export_btn.clicked.connect(self.export_vlan_analysis); rule_actions.addWidget(self.rule_export_btn); self.rule_remove_btn=QPushButton("Remove selected rule"); self.rule_remove_btn.setObjectName("secondary"); self.rule_remove_btn.clicked.connect(self.remove_intended_rule); rule_actions.addWidget(self.rule_remove_btn); rule_actions.addStretch(); vl.addLayout(rule_actions)
        self.intended_rules=[]; self.intended_table=self.make_table(["Service type","From VLAN","To VLAN","Status"]); vl.addWidget(self.intended_table,1)
        self.rule_results=self.make_table(["Service type","Rule direction","Observed evidence","Assessment","Recommended check"]); vl.addWidget(self.rule_results,2)
        self.tabs.addTab(vlan_tab,"VLAN / rule analyzer")
        traffic_tab=QWidget(); ti=QVBoxLayout(traffic_tab); ti.setContentsMargins(10,10,10,10)
        ti_note=QLabel("Traffic intelligence summarizes the loaded mDNS packet set. Repeated query names without a matching same-name/type response record are investigation candidates only; mDNS response correlation is not one-to-one.")
        ti_note.setObjectName("sub"); ti_note.setWordWrap(True); ti.addWidget(ti_note)
        self.traffic_intel_text=QTextEdit(); self.traffic_intel_text.setReadOnly(True); self.traffic_intel_text.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap); ti.addWidget(self.traffic_intel_text,1)
        self.tabs.addTab(traffic_tab,"Traffic intelligence")
        chain_tab=QWidget(); chain_layout=QVBoxLayout(chain_tab); chain_layout.setContentsMargins(10,10,10,10)
        chain_note=QLabel("Correlates DNS-SD PTR → SRV/TXT → A/AAAA records across the loaded session, even when records arrive in separate packets. Completeness means evidence was observed in this capture, not that the service is necessarily reachable.")
        chain_note.setObjectName("sub"); chain_note.setWordWrap(True); chain_layout.addWidget(chain_note)
        self.chain_table=self.make_table(["Service instance","Service type","Target host","Port","Target addresses","TXT evidence","Observed records","Sources","Chain status","Conflicts","Resolved hostnames"])
        chain_layout.addWidget(self.chain_table,1); self.tabs.addTab(chain_tab,"Service chains")
        flow_tab=QWidget(); flow_layout=QVBoxLayout(flow_tab); flow_layout.setContentsMargins(10,10,10,10); flow_layout.setSpacing(10)
        flow_note=QLabel("Filter observed mDNS conversations by endpoint, multicast group, service type, or capture-relative time. Multicast destinations identify a group, not individual receivers.")
        flow_note.setObjectName("sub"); flow_note.setWordWrap(True); flow_layout.addWidget(flow_note)
        flow_controls=QHBoxLayout(); flow_controls.addWidget(QLabel("IP / endpoint")); self.flow_ip_filter=QLineEdit(); self.flow_ip_filter.setPlaceholderText("Any source or destination IP…"); self.flow_ip_filter.setClearButtonEnabled(True); flow_controls.addWidget(self.flow_ip_filter,2)
        flow_controls.addWidget(QLabel("Multicast group")); self.flow_group_filter=QComboBox(); self.flow_group_filter.addItem("All groups"); flow_controls.addWidget(self.flow_group_filter,1)
        flow_controls.addWidget(QLabel("Service type")); self.flow_service_filter=QComboBox(); self.flow_service_filter.addItem("All service types"); flow_controls.addWidget(self.flow_service_filter,1)
        flow_controls.addWidget(QLabel("Time range")); self.flow_time_filter=QComboBox(); self.flow_time_filter.addItems(["All captured time","Last 1 minute","Last 5 minutes","Last 15 minutes","Last hour"]); flow_controls.addWidget(self.flow_time_filter,1)
        self.flow_reset=QPushButton("Reset filters"); self.flow_reset.setObjectName("secondary"); flow_controls.addWidget(self.flow_reset); flow_layout.addLayout(flow_controls)
        self.flow_summary=QLabel("Showing all observed conversations"); self.flow_summary.setObjectName("sub"); flow_layout.addWidget(self.flow_summary)
        self.conversation_map=ConversationMap(); flow_layout.addWidget(self.conversation_map,2)
        self.flow_table=self.make_table(["Source (hostname / IP)","Destination (hostname / IP or group)","Delivery","Packets","Queries","Responses","First seen","Last seen"]); self.flow_table.setMaximumHeight(250); flow_layout.addWidget(self.flow_table,1); self.tabs.addTab(flow_tab,"Flows")
        self.conversation_map.flow_selected.connect(self.flow_edge_selected)
        self.flow_ip_filter.textChanged.connect(self.refresh_flow_view)
        self.flow_group_filter.currentTextChanged.connect(self.refresh_flow_view)
        self.flow_service_filter.currentTextChanged.connect(self.refresh_flow_view)
        self.flow_time_filter.currentTextChanged.connect(self.refresh_flow_view)
        self.flow_reset.clicked.connect(self.reset_flow_filters)
        # Unified investigation workspace: timeline, prioritized findings, and
        # conservative query/response candidates all drill into retained packet rows.
        investigation_tab=QWidget(); investigation_layout=QVBoxLayout(investigation_tab); investigation_layout.setContentsMargins(10,10,10,10); investigation_layout.setSpacing(8)
        investigation_note=QLabel("One evidence workspace for incident triage. Query/response links are candidates based on name/type and timing; mDNS multicast visibility does not prove delivery to a particular receiver.")
        investigation_note.setObjectName("sub"); investigation_note.setWordWrap(True); investigation_layout.addWidget(investigation_note)
        self.investigation_timeline=self.make_table(["Offset (s)","Packets","Queries","Responses","Distinct sources"]); self.investigation_timeline.setMaximumHeight(180); investigation_layout.addWidget(self.investigation_timeline)
        investigation_layout.addWidget(QLabel("Prioritized findings · select a finding to inspect related evidence"))
        self.investigation_findings=self.make_table(["Priority","Finding","Subject","Evidence","Suggested next step"]); investigation_layout.addWidget(self.investigation_findings,2)
        investigation_layout.addWidget(QLabel("Query / response correlation candidates · double-click to inspect the response packet"))
        self.investigation_correlations=self.make_table(["Question name","Type","Query source (hostname / IP)","Candidate responder (hostname / IP)","Delta (s)","Confidence","Evidence"]); investigation_layout.addWidget(self.investigation_correlations,2)
        self.tabs.addTab(investigation_tab,"Investigation")
        self.investigation_findings.cellDoubleClicked.connect(self.investigation_finding_selected)
        # Two-capture comparison with explicit packet-level evidence for each difference.
        compare_tab=QWidget(); compare_layout=QVBoxLayout(compare_tab); compare_layout.setContentsMargins(10,10,10,10); compare_layout.setSpacing(8)
        compare_note=QLabel("Compare a baseline PCAP/PCAPNG against the currently loaded session. Differences include advertised DNS-SD records, observed source devices, and traffic counters. Absence is not proof of outage; compare similar capture windows and observation points.")
        compare_note.setObjectName("sub"); compare_note.setWordWrap(True); compare_layout.addWidget(compare_note)
        compare_actions=QHBoxLayout(); self.baseline_btn=QPushButton("Load baseline capture"); self.baseline_btn.setObjectName("secondary"); self.baseline_btn.clicked.connect(self.load_comparison_baseline); compare_actions.addWidget(self.baseline_btn)
        self.run_capture_compare_btn=QPushButton("Compare baseline vs current session"); self.run_capture_compare_btn.clicked.connect(self.run_capture_comparison); compare_actions.addWidget(self.run_capture_compare_btn); compare_actions.addStretch(); compare_layout.addLayout(compare_actions)
        self.capture_compare_summary=QLabel("Load a baseline capture, then import the current capture or use the current retained session."); self.capture_compare_summary.setObjectName("sub"); self.capture_compare_summary.setWordWrap(True); compare_layout.addWidget(self.capture_compare_summary)
        self.capture_compare_table=self.make_table(["Category","Change","Subject","Baseline count","Current count","Evidence"]); compare_layout.addWidget(self.capture_compare_table,1)
        self.tabs.addTab(compare_tab,"Capture comparison")
        # Plain-language analytics: translate counts and record relationships into
        # cautious, actionable interpretations while retaining the evidence caveats.
        insights_tab=QWidget(); insights_layout=QVBoxLayout(insights_tab); insights_layout.setContentsMargins(16,14,16,14); insights_layout.setSpacing(10)
        insights_intro=QLabel("A plain-language interpretation of what this capture shows, what it might mean, and what to check next. Conclusions are limited to observed evidence.")
        insights_intro.setObjectName("sub"); insights_intro.setWordWrap(True); insights_layout.addWidget(insights_intro)
        # Temporal analytics: compare candidate query outcomes across capture-relative windows.
        temporal_header=QHBoxLayout(); temporal_header.addWidget(QLabel("Discovery over time · recurring patterns vs one-off bursts")); temporal_header.addStretch()
        self.temporal_refresh_btn=QPushButton("Analyze discovery patterns"); self.temporal_refresh_btn.setObjectName("secondary"); self.temporal_refresh_btn.clicked.connect(self.refresh_temporal_analytics); temporal_header.addWidget(self.temporal_refresh_btn); insights_layout.addLayout(temporal_header)
        self.temporal_summary=QLabel("Analyze the loaded capture to compare candidate responses and recurring query patterns."); self.temporal_summary.setObjectName("sub"); self.temporal_summary.setWordWrap(True); insights_layout.addWidget(self.temporal_summary)
        self.temporal_table=self.make_table(["Pattern","Question / service","Source","Queries","Candidate responses","Windows","Packet evidence","Source hostname"]); self.temporal_table.setMaximumHeight(220); insights_layout.addWidget(self.temporal_table)
        self.temporal_table.cellDoubleClicked.connect(self.temporal_pattern_selected)
        self.insights_text=QTextEdit(); self.insights_text.setReadOnly(True); self.insights_text.setAcceptRichText(True); insights_layout.addWidget(self.insights_text,1)
        insights_actions=QHBoxLayout(); self.insights_refresh_btn=QPushButton("Refresh interpretation"); self.insights_refresh_btn.setObjectName("secondary"); self.insights_refresh_btn.clicked.connect(self.refresh_plain_language_insights); insights_actions.addWidget(self.insights_refresh_btn); insights_actions.addStretch(); insights_layout.addLayout(insights_actions)
        self.tabs.addTab(insights_tab,"Plain-language insights")
        # Guided troubleshooting: choose a symptom, optionally scope to a service/client,
        # then walk through evidence and next checks without claiming a root cause.
        guided_tab=QWidget(); guided_layout=QVBoxLayout(guided_tab); guided_layout.setContentsMargins(16,14,16,14); guided_layout.setSpacing(10)
        guided_intro=QLabel("Describe the symptom, optionally enter a service name/type or client IP, and build an evidence-led investigation. Each step separates observations from hypotheses.")
        guided_intro.setObjectName("sub"); guided_intro.setWordWrap(True); guided_layout.addWidget(guided_intro)
        guided_controls=QHBoxLayout(); guided_controls.addWidget(QLabel("Problem")); self.guided_symptom=QComboBox()
        for key,label in SYMPTOMS: self.guided_symptom.addItem(label,key)
        guided_controls.addWidget(self.guided_symptom,2); guided_controls.addWidget(QLabel("Service / name")); self.guided_service=QLineEdit(); self.guided_service.setPlaceholderText("e.g. _airplay._tcp.local"); guided_controls.addWidget(self.guided_service,2)
        guided_controls.addWidget(QLabel("Client IP")); self.guided_client=QLineEdit(); self.guided_client.setPlaceholderText("optional"); guided_controls.addWidget(self.guided_client,1)
        self.guided_run_btn=QPushButton("Build troubleshooting plan"); self.guided_run_btn.clicked.connect(self.run_guided_troubleshooting); guided_controls.addWidget(self.guided_run_btn); guided_layout.addLayout(guided_controls)
        self.guided_summary=QLabel("Ready when a capture or session is loaded."); self.guided_summary.setObjectName("sub"); self.guided_summary.setWordWrap(True); guided_layout.addWidget(self.guided_summary)
        guided_layout.addWidget(QLabel("Ranked possible causes · scores are investigation priorities, not probabilities · double-click to inspect supporting packets"))
        self.guided_causes_table=self.make_table(["Rank","Possible cause","Priority score","Evidence that supports it","Evidence that weakens it","Next useful test"]); self.guided_causes_table.setMaximumHeight(250); guided_layout.addWidget(self.guided_causes_table)
        self.guided_causes_table.cellDoubleClicked.connect(self.guided_cause_selected)
        self.guided_plan_text=QTextEdit(); self.guided_plan_text.setReadOnly(True); self.guided_plan_text.setAcceptRichText(True); guided_layout.addWidget(self.guided_plan_text,2)
        guided_layout.addWidget(QLabel("Matching packet evidence · double-click a row to open it in Live traffic"))
        self.guided_evidence_table=self.make_table(["Packet index","Time","Direction","Source (hostname / IP)","Destination (hostname / IP)","Evidence summary"]); guided_layout.addWidget(self.guided_evidence_table,2)
        self.guided_evidence_table.cellDoubleClicked.connect(self.guided_evidence_selected)
        self.tabs.addTab(guided_tab,"Guided troubleshooting")
        self._baseline_packets=None; self._baseline_label=""
        self.investigation_correlations.cellDoubleClicked.connect(self.investigation_correlation_selected)
        self.chain_table.cellDoubleClicked.connect(self.service_chain_selected)
        for cat in sorted({x.get("category","Other") for x in self.catalog_data}): self.catalog_category.addItem(cat)
        self.catalog_category.currentTextChanged.connect(self.refresh_catalog); self.refresh_catalog()
        # A workspace selector replaces the crowded row of tabs. Pages remain
        # ordinary QTabWidget pages so existing drill-down and selection logic works.
        self.tabs.tabBar().hide()
        for tab_index in range(self.tabs.count()):
            self.workspace_picker.addItem(self.tabs.tabText(tab_index), tab_index)
        self.workspace_picker.currentIndexChanged.connect(self._workspace_selected)
        self.tabs.currentChanged.connect(self._workspace_changed)
        foot=QHBoxLayout(); self.status=QLabel("Ready · Passive capture only"); self.status.setObjectName("sub"); foot.addWidget(self.status); foot.addStretch(); clear=QPushButton("Clear session"); clear.setObjectName("secondary"); clear.clicked.connect(self.clear_session); foot.addWidget(clear); layout.addLayout(foot)
        if self.interface_error:
            self.status.setText(self.interface_error)
        if getattr(self, "catalog_load_error", ""):
            self.status.setText(self.catalog_load_error)
        self.refresh_debounce=QTimer(self); self.refresh_debounce.setSingleShot(True); self.refresh_debounce.timeout.connect(self.refresh)
        self.discovery_refresh_timer=QTimer(self); self.discovery_refresh_timer.setSingleShot(True); self.discovery_refresh_timer.setInterval(300); self.discovery_refresh_timer.timeout.connect(self.refresh_discovery_view); self._discovery_dirty=True
        self._dashboard_signature=None; self._tab_render_signatures={}; self._persistent_row_filters={}; self._drilldown_history=[]; self._service_inventory={}
        self.update_drilldown_banner()
        self.timer=QTimer(self); self.timer.timeout.connect(self.refresh); self.timer.start(3500); self.comparison_debounce=QTimer(self); self.comparison_debounce.setSingleShot(True); self.comparison_debounce.setInterval(400); self.comparison_debounce.timeout.connect(self.refresh_comparison); self.refresh()
    def load_service_catalog(self):
        path=resource_path("service_catalog.json", __file__)
        try:
            data=json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                raise ValueError(f"unexpected format: {path}")
            self._curated_catalog=data
            bundled_path=resource_path("community_service_catalog.json", __file__)
            community=json.loads(bundled_path.read_text(encoding="utf-8"))
            community=validate_cached_entries(community)
            cache_path=self.community_catalog_cache_path()
            self._community_catalog_meta={}
            if cache_path.is_file():
                try:
                    cached=json.loads(cache_path.read_text(encoding="utf-8"))
                    community=validate_cached_entries(cached.get("entries"))
                    self._community_catalog_meta=cached
                except Exception as cache_error:
                    self.catalog_load_error=f"Saved community catalog could not be used; bundled data loaded instead: {cache_error}"
            self._community_catalog=community
            return merge_service_catalogs(self._curated_catalog, community)
        except Exception as exc:
            self.catalog_load_error = f"Could not load service catalog at {path}: {exc}"
            return []
    @staticmethod
    def community_catalog_cache_path():
        data_dir=Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation))
        return data_dir / "community_service_catalog.json"
    def refresh_catalog_update_status(self):
        if not hasattr(self,"catalog_update_status"): return
        count=len(getattr(self,"_community_catalog",[]) or [])
        fetched=(getattr(self,"_community_catalog_meta",{}) or {}).get("fetched_at")
        if fetched:
            self.catalog_update_status.setText(f"{count:,} community entries · saved update from {fetched} · source: bbusse/mdns-discover (BSD-3-Clause)")
        else:
            self.catalog_update_status.setText(f"{count:,} community entries included · select Update to check for a newer community catalog · source: bbusse/mdns-discover (BSD-3-Clause)")
    def update_community_catalog(self):
        if getattr(self,"_catalog_update_thread",None) and self._catalog_update_thread.is_alive(): return
        self.catalog_update_btn.setEnabled(False)
        self.catalog_update_status.setText("Checking the community catalog on GitHub…")
        def fetch():
            try:
                result=fetch_community_catalog()
            except Exception as exc:
                result={"error":str(exc)}
            self.bus.catalog_update_finished.emit(result)
        self._catalog_update_thread=threading.Thread(target=fetch,name="community-catalog-update",daemon=True)
        self._catalog_update_thread.start()
    def on_community_catalog_fetched(self, result):
        self.catalog_update_btn.setEnabled(True)
        if not isinstance(result,dict) or result.get("error"):
            error=(result or {}).get("error","Unexpected response") if isinstance(result,dict) else "Unexpected response"
            self.catalog_update_status.setText("Community catalog update failed; the current catalog remains available.")
            QMessageBox.warning(self,"Catalog update failed",f"Could not update the community catalog:\n\n{error}")
            return
        try:
            entries=validate_cached_entries(result.get("entries"))
        except Exception as exc:
            self.catalog_update_status.setText("Community catalog update failed validation; the current catalog remains available.")
            QMessageBox.warning(self,"Catalog validation failed",str(exc)); return
        existing={str(x.get("type") or "").lower():x for x in getattr(self,"_community_catalog",[])}
        added=sum(1 for entry in entries if entry["type"] not in existing)
        changed=sum(1 for entry in entries if entry["type"] in existing and (entry.get("name")!=existing[entry["type"]].get("name") or entry.get("description")!=existing[entry["type"]].get("description")))
        answer=QMessageBox.question(self,"Review community catalog update",
            f"The update contains {len(entries):,} validated service types.\n\n"
            f"New entries: {added:,}\nChanged entries: {changed:,}\n\n"
            "Confirm to save the refreshed community entries. App-curated entries will keep their own names and explanations. "
            "The downloaded file contains catalog text only; it cannot run code.\n\n"
            f"Source: {COMMUNITY_CATALOG_SOURCE}",
            QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)
        if answer!=QMessageBox.StandardButton.Yes:
            self.refresh_catalog_update_status(); return
        try:
            cache_path=self.community_catalog_cache_path(); cache_path.parent.mkdir(parents=True,exist_ok=True)
            payload={"source":result.get("source"),"source_url":result.get("source_url"),"fetched_at":result.get("fetched_at"),"upstream_last_modified":result.get("upstream_last_modified"),"entries":entries}
            temporary=cache_path.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(payload,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
            os.replace(temporary,cache_path)
            self._community_catalog=entries; self._community_catalog_meta=payload
            self.catalog_data=merge_service_catalogs(self._curated_catalog,entries)
            self.catalog_category.blockSignals(True); self.catalog_category.clear(); self.catalog_category.addItem("All categories")
            for category in sorted({x.get("category","Other") for x in self.catalog_data}): self.catalog_category.addItem(category)
            self.catalog_category.blockSignals(False)
            current_rule=self.rule_service.currentText()
            self.rule_service.clear()
            for item in self.catalog_data: self.rule_service.addItem(f"{item.get('name','')} — {item.get('type','')}",item.get("type",""))
            self.rule_service.setEditText(current_rule)
            self.refresh_catalog(); self.refresh_catalog_update_status()
            self.bus.status.emit(f"Community catalog updated: {len(entries):,} entries")
        except Exception as exc:
            QMessageBox.critical(self,"Could not save catalog update",f"The update was not installed. The prior catalog remains in use.\n\n{exc}")
    def refresh_catalog(self, *_):
        if not hasattr(self,"catalog_table"): return
        query=self.catalog_search.text().strip().lower()
        category=self.catalog_category.currentText()
        rows=[]
        for item in self.catalog_data:
            if category!="All categories" and item.get("category")!=category: continue
            hay=" ".join(str(item.get(k,"")) for k in ("name","type","transport","category","description","r1")).lower()
            if query and query not in hay: continue
            rows.append([item.get("name",""),item.get("type",""),item.get("transport",""),item.get("category",""),item.get("description",""),item.get("r1","")])
        self.fill_table(self.catalog_table,rows)
    def export_rule_planner(self):
        path,_=QFileDialog.getSaveFileName(self,"Export RUCKUS One rule planner","ruckus-one-mdns-rule-planner.csv","CSV files (*.csv)")
        if not path: return
        try:
            with open(path,"w",newline="",encoding="utf-8-sig") as f:
                fields=["friendly_name","dns_sd_service_type","transport_protocol","category","purpose","ruckus_one_guidance","from_vlan","to_vlan","enabled","notes"]
                w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
                for item in self.catalog_data:
                    w.writerow({"friendly_name":item.get("name",""),"dns_sd_service_type":item.get("type",""),"transport_protocol":item.get("transport",""),"category":item.get("category",""),"purpose":item.get("description",""),"ruckus_one_guidance":item.get("r1",""),"from_vlan":"","to_vlan":"","enabled":"No - review first","notes":"Confirm exact predefined service name and service-type syntax in your RUCKUS One tenant before creating a rule."})
            QMessageBox.information(self,"Rule planner exported",f"Saved {len(self.catalog_data)} catalog entries to:\n{path}")
            self.bus.status.emit("R1 rule planner CSV exported")
        except Exception as e: QMessageBox.critical(self,"Export failed",str(e))
    def add_intended_rule(self):
        raw=self.rule_service.currentData() or self.rule_service.currentText()
        # Combo text can include a friendly name and type; normalize to the DNS-SD token.
        m=re.search(r"_[A-Za-z0-9-]+\._(?:tcp|udp)(?:\.local)?", str(raw), re.I)
        if not m: m=re.search(r"_[A-Za-z0-9-]+\._(?:tcp|udp)(?:\.local)?", self.rule_service.currentText(), re.I)
        service=m.group(0).lower().removesuffix('.local') if m else str(raw).strip().lower()
        frm=self.rule_from.text().strip(); to=self.rule_to.text().strip()
        if not service or not frm or not to:
            QMessageBox.warning(self,"Rule needs details","Select/type a DNS-SD service type and enter both VLAN IDs."); return
        if frm==to:
            QMessageBox.warning(self,"Invalid VLAN direction","From VLAN and To VLAN must be different."); return
        rule={"service":service,"from":frm,"to":to}
        if rule not in self.intended_rules: self.intended_rules.append(rule)
        self.refresh_intended_rules(); self.analyze_vlan_rules()
    def refresh_intended_rules(self):
        self.fill_table(self.intended_table,[[r['service'],r['from'],r['to'],"Planning only · not deployed"] for r in self.intended_rules])
    def remove_intended_rule(self):
        row=self.intended_table.currentRow()
        if row < 0: return
        service=self.intended_table.item(row,0).text() if self.intended_table.item(row,0) else ""
        frm=self.intended_table.item(row,1).text() if self.intended_table.item(row,1) else ""
        to=self.intended_table.item(row,2).text() if self.intended_table.item(row,2) else ""
        for i, rule in enumerate(self.intended_rules):
            if rule.get("service")==service and str(rule.get("from"))==frm and str(rule.get("to"))==to:
                self.intended_rules.pop(i); self.refresh_intended_rules(); self.analyze_vlan_rules(); return
    def analyze_vlan_rules(self):
        snap=self.an.snapshot(); packets=snap.get("packets",[]); rows=[]
        for rule in self.intended_rules:
            service=rule['service'].lower().rstrip('.')
            matched=[]
            for pkt in packets:
                vlan=str(pkt.get('vlan','Unknown / not tagged'))
                names=[str(q.get('name','')).lower().rstrip('.') for q in pkt.get('questions',[])]
                names += [str(rr.get('name','')).lower().rstrip('.') for rr in pkt.get('records',[])]
                if any(service in n for n in names): matched.append((pkt,vlan))
            from_hits=sum(1 for pkt,v in matched if v==rule['from'] and pkt.get('direction')=='Response')
            to_hits=sum(1 for pkt,v in matched if v==rule['to'] and pkt.get('direction')=='Query')
            unknown=sum(1 for pkt,v in matched if 'Unknown' in v)
            if not matched: assessment='No matching service traffic observed'; evidence='0 matching packets'
            elif from_hits and to_hits: assessment='Evidence on both sides'; evidence=f'{len(matched)} matching packets; source responses={from_hits}; destination queries={to_hits}'
            elif unknown: assessment='VLAN attribution incomplete'; evidence=f'{len(matched)} matching packets; {unknown} with unknown/untagged VLAN'
            else: assessment='Only one side or direction observed'; evidence=f'{len(matched)} matching packets; source responses={from_hits}; destination queries={to_hits}'
            recommendation='Verify AP/VLAN capture points, service type, rule direction, proxy instance scope, and client isolation; absence in a capture is not proof of a forwarding failure.'
            rows.append([service,f"{rule['from']} → {rule['to']}",evidence,assessment,recommendation])
        if not rows: rows=[["—","Add a rule above","No intended rules configured","No analysis yet","Add service + From VLAN + To VLAN, then analyze."]]
        self.fill_table(self.rule_results,rows)
        self.bus.status.emit(f"VLAN/rule analysis complete · {len(self.intended_rules)} intended rules · read-only")
    def export_vlan_analysis(self):
        path,_=QFileDialog.getSaveFileName(self,"Export VLAN rule analysis","mdns-vlan-rule-analysis.csv","CSV files (*.csv)")
        if not path: return
        try:
            with open(path,'w',newline='',encoding='utf-8-sig') as f:
                w=csv.writer(f); w.writerow(["service_type","from_vlan","to_vlan","deployment_status","observed_evidence","assessment","recommended_check"])
                snap=self.an.snapshot(); packets=snap.get('packets',[])
                for rule in self.intended_rules:
                    service=rule['service'].lower().rstrip('.'); matched=[]
                    for pkt in packets:
                        names=[str(q.get('name','')).lower().rstrip('.') for q in pkt.get('questions',[])] + [str(rr.get('name','')).lower().rstrip('.') for rr in pkt.get('records',[])]
                        if any(service in n for n in names): matched.append(pkt)
                    evidence=f"{len(matched)} matching packets; VLANs="+", ".join(sorted({str(p.get('vlan','Unknown')) for p in matched}))
                    w.writerow([service,rule['from'],rule['to'],'Planning only - not deployed',evidence,'See UI assessment','Verify capture points and RUCKUS One rule direction; no automatic changes made.'])
            QMessageBox.information(self,"Export complete",f"Exported {len(self.intended_rules)} rule assessments to:\n{path}")
        except Exception as e: QMessageBox.critical(self,"Export failed",str(e))
    def make_table(self,headers):
        t=QTableWidget(0,len(headers)); t.setHorizontalHeaderLabels(headers); t.setAlternatingRowColors(True)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.setShowGrid(False); t.setWordWrap(False); t.setTextElideMode(Qt.TextElideMode.ElideRight)
        t.verticalHeader().setVisible(False); t.verticalHeader().setDefaultSectionSize(36)
        header=t.horizontalHeader(); header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setDefaultSectionSize(155); header.setMinimumSectionSize(90); header.setStretchLastSection(True)
        t.setSortingEnabled(True); header.setSortIndicatorShown(True); t.setToolTip("Click any column header to sort; click again to reverse the order. Hover over truncated values to see the full text.")
        # Persist widths by stable table schema; avoid per-event disk writes during active discovery.
        schema="|".join(headers); key="tableWidths/"+schema
        saved=self.settings.value(key, []) if hasattr(self,"settings") else []
        if isinstance(saved, list) and len(saved)==len(headers):
            for i,w in enumerate(saved):
                try: t.setColumnWidth(i,max(70,int(w)))
                except (TypeError,ValueError): pass
        header.sectionResized.connect(lambda *_args, table=t, k=key: self.save_table_widths(table,k))
        return t
    def populate_interfaces(self):
        self.iface.addItem("Default interface", "")
        self.interface_error = ""
        if not SCAPY_OK:
            self.interface_error = "Scapy is unavailable; live capture cannot start until dependencies are installed."
            self.iface.setToolTip(self.interface_error)
            return
        try:
            interfaces = sorted(set(get_if_list()))
            for name in interfaces:
                self.iface.addItem(name, name)
            if not interfaces:
                self.interface_error = "Scapy returned no interfaces. Check the capture backend and network permissions."
        except Exception as exc:
            self.interface_error = f"Could not enumerate network interfaces: {exc}"
        if self.interface_error:
            self.iface.setToolTip(self.interface_error)
    def on_source_filter_changed(self, *_):
        mode = self.source_filter.currentData()
        if hasattr(self, "settings"):
            self.settings.setValue("trafficSourceFilter", mode)
        label = {"all": "All traffic sources", "erspan": "ERSPAN tunnel only", "local": "Local traffic only"}.get(mode, "All traffic sources")
        self._dashboard_signature = None
        self._tab_render_signatures.clear()
        self.refresh()
        self.bus.status.emit(f"Traffic source filter · {label} · capture remains active")

    def refresh_interfaces(self):
        if self.capture and self.capture.is_alive():
            QMessageBox.information(self, "Capture is running", "Stop live capture before refreshing the interface list.")
            return
        current = self.iface.currentData() or ""
        self.iface.blockSignals(True)
        self.iface.clear()
        self.populate_interfaces()
        index = self.iface.findData(current)
        if index >= 0:
            self.iface.setCurrentIndex(index)
        self.iface.blockSignals(False)
        if self.interface_error:
            self.bus.status.emit("Interface refresh · " + self.interface_error)
        else:
            self.bus.status.emit(f"Interface list refreshed · {max(0, self.iface.count()-1)} interface(s)")

    def show_runtime_diagnostics(self):
        interfaces = [self.iface.itemData(i) for i in range(1, self.iface.count())]
        discovery_errors = [e.get("error", e.get("status", "Unknown error")) for e in self.discovery_events if e.get("event") in ("error", "resolve_error")]
        data = runtime_diagnostics(
            app_version=APP_VERSION, interfaces=interfaces,
            selected_interface=self.iface.currentText(),
            capture_error=self.an.capture_error, discovery_errors=discovery_errors,
            scapy_available=SCAPY_OK,
        )
        box = QMessageBox(self)
        box.setWindowTitle("mDNS Observatory · Runtime diagnostics")
        box.setIcon(QMessageBox.Icon.Information)
        box.setText("Runtime and capture environment")
        box.setInformativeText("Copy these details when reporting a startup, capture, or Bonjour discovery issue.")
        box.setDetailedText(format_runtime_diagnostics(data))
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.exec()

    def export_support_bundle(self):
        answer = QMessageBox.warning(
            self, "Export support bundle",
            "The bundle excludes raw packet rows and payloads, but may include interface names, host/service names, addresses, and error text from recent Bonjour events. Review it before sharing. Continue?",
            QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Save:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export mDNS Observatory support bundle",
            "mdns-observatory-support.zip", "ZIP support bundle (*.zip)"
        )
        if not path:
            return
        if not path.lower().endswith(".zip"):
            path += ".zip"
        try:
            interfaces = [self.iface.itemData(i) for i in range(1, self.iface.count())]
            discovery_errors = [e.get("error", e.get("status", "Unknown error")) for e in self.discovery_events if e.get("event") in ("error", "resolve_error")]
            diagnostics = runtime_diagnostics(
                app_version=APP_VERSION, interfaces=interfaces,
                selected_interface=self.iface.currentText(), capture_error=self.an.capture_error,
                discovery_errors=discovery_errors, scapy_available=SCAPY_OK,
            )
            build_support_bundle(path, diagnostics=diagnostics,
                analyzer_snapshot=self.an.snapshot(include_packets=False),
                discovery_events=self.discovery_events, app_version=APP_VERSION)
            self.bus.status.emit("Support bundle exported · " + Path(path).name)
            QMessageBox.information(self, "Support bundle exported", f"Saved support bundle to:\n{path}\n\nRaw packet rows and payloads were not included.")
        except Exception as exc:
            QMessageBox.critical(self, "Support bundle export failed", str(exc))

    def set_status(self,s): self.status.setText(s)
    def toggle_capture(self):
        if self.capture and self.capture.is_alive():
            self.an.stop_event.set(); self.start_btn.setText("Start capture"); self.bus.status.emit("Stopping capture…"); return
        if not SCAPY_OK:
            QMessageBox.warning(self,"Capture unavailable","Scapy is not installed. Reinstall the app dependencies, then restart the app."); return
        # Skip the reset prompt when there is nothing to clear.
        with self.an.lock:
            has_previous_results = bool(
                self.an.packets or self.an.devices or self.an.services
                or self.an.events or self.active_results or self.discovery_events
            )
        answer = QMessageBox.StandardButton.No
        if has_previous_results:
            answer = QMessageBox.question(
                self,
                "Start a new capture?",
                "Clear the current capture results before starting?\n\n"
                "Yes — clear previous results\n"
                "No — keep existing results and add to them\n"
                "Cancel — do not start capture",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Yes,
            )
        if answer == QMessageBox.StandardButton.Cancel:
            return
        if answer == QMessageBox.StandardButton.Yes:
            # Reset only the current analysis inventory; retain the selected
            # interface and loaded comparison baseline so the user can still
            # compare this fresh capture against a reference.
            with self.an.lock:
                self.an.packets.clear()
                self.an.devices.clear()
                self.an.services.clear()
                self.an.services_by_instance.clear()
                self.an.groups.clear()
                self.an.types.clear()
                self.an.events.clear()
                self.an.diagnostics.clear()
                self.an.started = None
                self.an.capture_error = ""
                self.an.revision += 1
            self.active_results.clear()
            self.discovery_events.clear()
            self._comparison_cache_key = None
            self._comparison_data = []
            self.refresh()
        iface=self.iface.currentData() or None
        if self.interface_error and not iface:
            answer = QMessageBox.warning(self, "Interface enumeration warning", self.interface_error + "\n\nTry the default interface anyway?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.an.stop_event.clear(); self.an.started=now_iso(); self.an.capture_error=""
        self.start_btn.setText("Stop capture"); self.bus.status.emit("Capturing passively · "+(iface or "default interface"))
        def run():
            sniffer = None
            try:
                # Keep one capture socket open for the whole session. Repeated calls
                # to sniff(timeout=1) repeatedly opened/closed the macOS BPF socket,
                # which can fail or silently capture nothing on some interfaces.
                kwargs = {"prn": self.an.ingest_live, "store": False}
                if iface:
                    kwargs["iface"] = iface
                sniffer = AsyncSniffer(**kwargs)
                sniffer.start()
                deadline = time.monotonic() + 2.0
                while not self.an.stop_event.wait(0.2):
                    # AsyncSniffer runs its socket loop on a worker thread. Surface
                    # an early BPF/socket failure instead of leaving the UI looking
                    # like it is capturing forever.
                    if not sniffer.running:
                        exc = getattr(sniffer, "exception", None)
                        if exc:
                            raise exc
                        break
                    # Update status once capture startup has succeeded. Packet
                    # counts are shown in Findings even when no mDNS is observed.
                    if time.monotonic() >= deadline:
                        d = self.an.snapshot().get("diagnostics", {})
                        seen = d.get("frames_seen", 0)
                        accepted = d.get("mdns_packets_accepted", 0)
                        self.bus.status.emit(
                            f"Live capture active · {iface or 'default interface'} · "
                            f"{seen:,} frames seen · {accepted:,} mDNS packets · "
                            f"{d.get('live_port_5353_not_decoded', 0):,} UDP/5353 decode misses"
                        )
                        deadline = time.monotonic() + 2.0
                if sniffer and sniffer.running:
                    sniffer.stop(join=True)
            except Exception as e:
                message = str(e).strip() or repr(e)
                message = capture_error_guidance(message)
                self.an.capture_error = message
                self.bus.status.emit("Capture error · " + message.splitlines()[0])
            finally:
                try:
                    if sniffer and sniffer.running:
                        sniffer.stop(join=True)
                except Exception:
                    pass
                if not self.an.capture_error:
                    self.bus.status.emit("Capture stopped")
                self.bus.changed.emit()
                self.bus.capture_finished.emit(self.an.capture_error)
        self.capture=threading.Thread(target=run,daemon=True); self.capture.start()
    def capture_finished(self, error_message=""):
        self.start_btn.setText("Start capture")
        self.start_btn.setEnabled(True)
        if error_message:
            self.bus.status.emit("Capture failed · " + error_message.splitlines()[0])
    def discovery_finished(self):
        self.set_discovery_controls(False)
    def set_discovery_controls(self, running, stopping=False):
        text = "Stopping Bonjour…" if stopping else ("Stop active discovery" if running else "Start active discovery")
        active_text = "Stopping Bonjour…" if stopping else ("Stop Bonjour discovery" if running else "Start Bonjour discovery")
        for button, label in ((self.browse_btn, active_text), (self.dashboard.discovery_btn, text)):
            button.setText(label)
            button.setEnabled(sys.platform == "darwin" and not stopping)
    def toggle_browse(self):
        if self.browser and self.browser.thread and self.browser.thread.is_alive():
            self.set_discovery_controls(True, stopping=True)
            self.bus.status.emit("Stopping Bonjour discovery and resolver processes…")
            self.browser.stop(); return
        types=[x.strip() for x in self.discovery_types.text().split(",") if x.strip()]
        if not types: types=DEFAULT_TYPES
        interface=self.iface.currentData() or ""
        try: ifindex=socket.if_nametoindex(interface) if interface else 0
        except OSError: ifindex=0
        def browser_status(message):
            self.bus.status.emit(message)
            if message.startswith("Bonjour discovery worker stopped"):
                self.bus.discovery_finished.emit()
        self.browser=BonjourBrowser(lambda item: self.bus.discovery_event.emit(item), browser_status, ifindex)
        self.set_discovery_controls(True)
        self.browser.start(types); self.bus.status.emit(f"Starting active Bonjour discovery · {len(types)} service types")

    def handle_discovery_event(self, item):
        item=dict(item); ev=item.get("event")
        if ev == "error":
            self.discovery_events.append(item); self._discovery_dirty=True; self.bus.status.emit("Bonjour error · "+item.get("error","unknown error")); self.refresh_discovery(); return
        key=(item.get("fullname") or item.get("instance","")).rstrip(".").lower()
        if not key: return
        if ev == "remove":
            if key in self.active_results:
                self.active_results[key]["status"]="Removed from browse results"
                self.active_results[key]["active"] = False
                self.active_results[key]["last_seen"]=item.get("last_seen",now_iso())
        elif ev in ("add","resolved"):
            current=self.active_results.get(key,{})
            current.update(item); current["active"] = True
            current["status"]="Resolved" if current.get("resolved") else "Discovered · resolving"
            self.active_results[key]=current
        elif ev == "resolve_error":
            current=self.active_results.setdefault(key,dict(item)); current["status"]=item.get("error","Resolve failed")
        self.discovery_events.append(item)
        if len(self.discovery_events)>5000: self.discovery_events=self.discovery_events[-5000:]
        self._discovery_dirty=True
        self.refresh_discovery()

    def clear_discoveries(self):
        self.active_results.clear(); self.discovery_events.clear(); self._discovery_dirty=True; self.refresh_discovery(); self._comparison_cache_key=None; self.bus.status.emit("Active discovery results cleared")

    def refresh_discovery(self):
        # Coalesce bursts of native DNS-SD events. Rebuilding QTableWidget rows
        # per event can block the UI while Bonjour resolves many instances.
        if not getattr(self, "_discovery_dirty", False):
            return
        if not self.discovery_refresh_timer.isActive():
            self.discovery_refresh_timer.start()

    def refresh_discovery_view(self):
        if not self._discovery_dirty:
            return
        self._discovery_dirty=False
        current = self.tabs.currentWidget()
        if current is self.active_table.parentWidget():
            items=sorted(self.active_results.values(),key=lambda x:(x.get("service_type",""),x.get("instance","")))
            self.fill_table(self.active_table,[[x.get("instance",x.get("fullname","")),x.get("service_type",""),x.get("host",""),x.get("port","") or "",x.get("txt",""),x.get("interface_index",0),x.get("status","Discovered"),x.get("last_seen","")] for x in items])
        elif current is getattr(self, "comparison_tab", None):
            self.comparison_debounce.start()
        elif current is self.dashboard:
            self.refresh()

    @staticmethod
    def norm_service(value):
        return str(value or "").rstrip(".").lower()

    def refresh_comparison(self):
        if self.tabs.currentWidget() is not getattr(self, "comparison_tab", None):
            return
        # Build from a compact immutable packet snapshot; no QTableWidget reads are
        # needed by exports, and repeated refreshes are debounced on tab entry.
        active = list(self.active_results.values())
        with self.an.lock:
            revision = self.an.revision
            cache_key = comparison_cache_key(id(self.an), revision, active)
            if cache_key == self._comparison_cache_key:
                rows = self._comparison_data
                packets = None
            else:
                packets = list(self.an.packets)
        if packets is not None:
            chains = build_service_chains(packets)
            rows = compare_discoveries(chains, active)
            self._comparison_data = rows
            self._comparison_cache_key = cache_key
        self.fill_table(self.compare_table, [[r["service_instance"], "Yes" if r["passive_seen"] else "No",
            "Yes" if r["active_seen"] else "No", r["target"], r["port"], r["interpretation"]] for r in rows])

    def save_session(self):
        path,_=QFileDialog.getSaveFileName(self,"Save mDNS Observatory session","mdns-observatory-session.json","JSON session (*.json)")
        if not path: return
        try:
            snap=self.an.snapshot(include_packets=True)
            snap["session_format"]="mdns-observatory-session-v1"
            snap["application_version"]=APP_VERSION
            snap["active_discoveries"]=list(self.active_results.values())
            snap["discovery_events"]=list(self.discovery_events)
            snap["intended_rules"]=list(getattr(self,"intended_rules",[]))
            Path(path).write_text(json.dumps(snap,indent=2,ensure_ascii=False,default=list),encoding="utf-8")
            self.bus.status.emit(f"Session saved: {Path(path).name}")
        except Exception as e: QMessageBox.critical(self,"Save session failed",str(e))

    def open_session(self):
        if self.capture and self.capture.is_alive():
            QMessageBox.information(self,"Capture active","Stop live capture before opening a saved session so new packets are not mixed into the saved dataset.")
            return
        path,_=QFileDialog.getOpenFileName(self,"Open mDNS Observatory session","","Session JSON (*.json)")
        if not path: return
        try:
            data=json.loads(Path(path).read_text(encoding="utf-8"))
            payload=validate_session_payload(data)  # validate before mutating current state
            staged=Analyzer()
            capture_started = data.get("capture_started")
            staged.started = capture_started if isinstance(capture_started, str) else now_iso()
            for packet in payload["packets"]:
                staged.ingest_decoded(packet)
            # Restore capture-wide diagnostics, but keep packet-derived counters
            # aligned with the retained packet history replayed above. A truncated
            # session may have historical totals larger than its stored evidence.
            for key,value in restore_diagnostics(data.get("diagnostics", {}), len(payload["packets"])).items():
                staged.diagnostics[key]=value
            self.an=staged
            self.active_results={str(i):x for i,x in enumerate(payload["active_discoveries"])}
            self._comparison_data=[]; self._comparison_cache_key=None
            self.discovery_events=payload["discovery_events"]
            self.intended_rules=payload["intended_rules"]
            self.refresh_intended_rules(); self.analyze_vlan_rules()
            self.refresh_catalog(); self.refresh(); self.refresh_discovery()
            self.refresh_comparison_if_visible()
            self.bus.status.emit(f"Session opened: {Path(path).name} · {len(self.an.packets):,} stored packets")
            if payload.get("packet_history_truncated"):
                QMessageBox.warning(self, "Session history was truncated",
                    "This session was saved after the 100,000-packet retention limit was reached. Only the newest stored packet observations are available, so derived counters rebuilt from this session may differ from the original live-run totals.")
        except Exception as e: QMessageBox.critical(self,"Open session failed",str(e))

    def refresh_comparison_if_visible(self):
        if self.tabs.currentWidget() is getattr(self, "comparison_tab", None):
            self.refresh_comparison()

    def device_chart_drilldown(self,label,category):
        self.tabs.setCurrentIndex(2)
        needle=str(label).casefold()
        self.set_persistent_row_filter(self.device_table, lambda cells: needle in cells[0].casefold(), f"Device: {label}")
        self.bus.status.emit(f"Device inventory filtered to {label}")

    def selected_device_ip(self):
        row=self.device_table.currentRow()
        item=self.device_table.item(row,0) if row>=0 else None
        return item.text() if item else ""

    def update_device_health(self):
        ip=self.selected_device_ip()
        if not ip:
            self.device_health.setText("Select a device to see health indicators")
            return
        with self.an.lock:
            d=self.an.devices.get(ip,{})
            recent=d.get("last_seen","")
            packets=int(d.get("packets",0)); queries=int(d.get("queries",0)); responses=int(d.get("responses",0))
        ratio=queries/max(1,responses)
        status="High query activity" if queries>=20 and ratio>=5 else ("Observed" if packets else "No packet evidence")
        self.device_health.setText(f"{status}  ·  {packets:,} packets  ·  {queries:,} queries / {responses:,} responses  ·  last seen {recent or 'unknown'}")

    def selected_device_chains(self):
        ip=self.selected_device_ip()
        if not ip: return
        self.refresh()
        self.tabs.setCurrentIndex(11)
        needle=ip.casefold()
        self.set_persistent_row_filter(self.chain_table, lambda cells: needle in cells[7].casefold(), f"Source: {ip}")
        self.bus.status.emit(f"Service chains filtered to source {ip}")

    def selected_device_packets(self):
        ip=self.selected_device_ip()
        if not ip: return
        self.refresh()
        self.tabs.setCurrentIndex(1)
        self.set_persistent_row_filter(self.packet_table, lambda cells: cells[3] == ip or cells[4] == ip, f"Device packets: {ip}")
        self.bus.status.emit(f"Packet evidence filtered to {ip}")

    def selected_service_instance(self):
        row=self.service_table.currentRow()
        item=self.service_table.item(row,0) if row>=0 else None
        return item.text() if item else ""

    @staticmethod
    def normalize_service_type(value):
        return str(value or "").strip().lower().rstrip(".").removesuffix(".local")

    def service_catalog_entry(self, service_type):
        wanted=self.normalize_service_type(service_type)
        return next((entry for entry in self.catalog_data if self.normalize_service_type(entry.get("type"))==wanted), {})

    def update_service_explanation_action(self):
        if hasattr(self,"service_explain_btn"):
            self.service_explain_btn.setEnabled(self.service_table.currentRow() >= 0)

    def explain_selected_service(self):
        instance=self.selected_service_instance()
        service=getattr(self,"_service_inventory",{}).get(instance)
        if not service: return
        ServiceExplanationDialog([service],self.catalog_data,f"Selected service: {instance}",self).exec()

    def service_chart_drilldown(self,label,category):
        self.tabs.setCurrentIndex(3)
        needle=str(label).casefold()
        self.set_persistent_row_filter(self.service_table, lambda cells: needle in cells[1].casefold(), f"Service type: {label}")
        self.bus.status.emit(f"Service inventory filtered to {label}")

    def service_health_drilldown(self,label,category):
        self.refresh()
        self.tabs.setCurrentIndex(11)
        needle=str(label).casefold()
        self.set_persistent_row_filter(self.chain_table, lambda cells: needle in (cells[8] + " " + cells[9]).casefold() or (needle == "conflicts" and "conflict" in (cells[8] + " " + cells[9]).casefold()), f"Chain health: {label}")
        self.bus.status.emit(f"Service chains filtered by health: {label}")

    def selected_service_chain(self):
        instance=self.selected_service_instance()
        if not instance: return
        self.refresh()
        self.tabs.setCurrentIndex(11)
        needle=instance.casefold()
        self.set_persistent_row_filter(self.chain_table, lambda cells: cells[0].casefold() == needle, f"Service chain: {instance}")
        for row in range(self.chain_table.rowCount()):
            if not self.chain_table.isRowHidden(row): self.chain_table.selectRow(row)
        self.bus.status.emit(f"Opened service chain for {instance}")

    def selected_service_packets(self):
        instance=self.selected_service_instance()
        if not instance: return
        self.refresh()
        self.tabs.setCurrentIndex(1)
        needle=instance.casefold()
        self.set_persistent_row_filter(self.packet_table, lambda cells: needle in cells[6].casefold(), f"Service packets: {instance}")
        self.bus.status.emit(f"Packet evidence filtered to service {instance}")

    def service_row_drilldown(self,row,column=0):
        self.service_table.selectRow(row)
        self.selected_service_chain()

    def inspect_device(self, row, column=0):
        ip_item=self.device_table.item(row,0)
        if not ip_item: return
        display=ip_item.text()
        match=re.search(r"\(([^()]+)\)\s*$",display)
        ip=match.group(1) if match else display
        with self.an.lock:
            raw_device=self.an.devices.get(ip)
            if not raw_device: return
            device={**raw_device,"hostnames":sorted(raw_device["hostnames"]),"services":sorted(raw_device["services"])}
            observed_services=[]
            device_names={str(name).casefold().rstrip(".") for name in device.get("hostnames",[])}
            references={str(name).casefold().rstrip(".") for name in device.get("services",[])}
            for service in self.an.services.values():
                sources=set(service.get("sources",set()))
                target=str(service.get("target") or "").casefold().rstrip(".")
                instance=str(service.get("instance") or "").casefold().rstrip(".")
                service_type=str(service.get("service_type") or "").casefold().rstrip(".")
                source_match=ip in sources
                target_match=ip.casefold() in target or any(name and name in target for name in device_names)
                reference_match=any(name and (name==instance or name==service_type or name in instance) for name in references)
                if source_match or target_match or reference_match:
                    observed_services.append({**service,"sources":sorted(sources),"txt":list(service.get("txt",[]))})
            observed_services.sort(key=lambda item:(str(item.get("service_type","")),str(item.get("instance",""))))
        hostnames=", ".join(device.get("hostnames",[])) or "no hostname learned"
        context=(f"Device {hostnames} · {ip} · MAC {device.get('mac') or 'unavailable'} · VLAN {device.get('vlan','Unknown')}\n"
                 f"Observed {device.get('packets',0):,} packets ({device.get('queries',0):,} queries / {device.get('responses',0):,} responses) · "
                 f"last seen {device.get('last_seen') or 'unknown'} · services are included when this device advertised them or matched an observed SRV target.")
        ServiceExplanationDialog(observed_services,self.catalog_data,context,self).exec()

    def inspect_selected_device(self):
        row=self.device_table.currentRow()
        if row>=0: self.inspect_device(row)

    def load_comparison_baseline(self):
        if self.capture and self.capture.is_alive():
            QMessageBox.information(self,"Capture active","Stop live capture before loading a comparison baseline."); return
        path,_=QFileDialog.getOpenFileName(self,"Load baseline capture","","Packet captures (*.pcap *.pcapng *.cap);;All files (*)")
        if not path: return
        packets=[]; frames=0; errors=0
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            for ts,linktype,frame in read_capture(path):
                frames+=1
                try:
                    info=decode_frame(frame,linktype,ts)
                    if info:
                        info.setdefault("capture_origin", info.get("source_type", "local"))
                        info["capture_method"]="pcap"
                        packets.append(info)
                except Exception:
                    errors+=1
            if not frames:
                raise ValueError("The selected file contained no readable frames.")
            self._baseline_packets=packets; self._baseline_label=Path(path).name
            self.capture_compare_summary.setText(f"Baseline loaded: {self._baseline_label} · {frames:,} frames · {len(packets):,} decoded mDNS packets · {errors} decode errors. Current session will be compared when you run the comparison.")
            self.bus.status.emit(f"Comparison baseline loaded · {len(packets):,} mDNS packets")
        except Exception as exc:
            QMessageBox.critical(self,"Baseline load failed",str(exc))
        finally:
            QApplication.restoreOverrideCursor()

    def run_capture_comparison(self):
        if self._baseline_packets is None:
            QMessageBox.information(self,"Baseline required","Load a baseline PCAP or PCAPNG first."); return
        with self.an.lock:
            current=list(self.an.packets)
        result=compare_captures(self._baseline_packets,current,self._baseline_label or "Baseline","Current session")
        rows=[]
        for d in result["differences"]:
            rows.append([d["category"],d["change"],d["subject"],d["baseline_count"],d["current_count"],d["evidence"]])
        self.fill_table(self.capture_compare_table,rows)
        a=result["baseline"]; b=result["current"]
        note=" · ".join(result["notes"])
        self.capture_compare_summary.setText(f"Baseline: {a['packet_count']:,} mDNS packets, {a['record_count']:,} record observations, {a['device_count']:,} source IPs. Current: {b['packet_count']:,} mDNS packets, {b['record_count']:,} record observations, {b['device_count']:,} source IPs. Differences: {len(rows)}. {note}")
        self.bus.status.emit(f"Capture comparison complete · {len(rows)} evidence-backed differences")

    def import_pcap(self):
        if self.capture and self.capture.is_alive():
            QMessageBox.information(self,"Capture active","Stop live capture before importing a file so the imported dataset stays separate from live traffic.")
            return
        path,_=QFileDialog.getOpenFileName(self,"Import packet capture","","Packet captures (*.pcap *.pcapng *.cap);;All files (*)")
        if not path: return
        self.bus.status.emit("Reading capture…"); QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            # Build a separate analyzer so a failed import never destroys the current session.
            staged=Analyzer(); frames=0; mdns=0; unsupported=0; decode_errors=0
            for ts,linktype,frame in read_capture(path):
                frames += 1
                staged.diagnostics["frames_seen"] += 1
                try:
                    info=decode_frame(frame,linktype,ts)
                    if info:
                        info.setdefault("capture_origin", info.get("source_type", "local"))
                        info["capture_method"]="pcap"
                        staged.ingest_decoded(info); mdns += 1
                    else:
                        unsupported += 1
                except Exception as exc:
                    decode_errors += 1
                    staged.diagnostics["import_decode_errors"] += 1
                    if not staged.capture_error: staged.capture_error=f"Frame {frames}: {exc}"
            staged.diagnostics["import_frames_total"] = frames
            staged.diagnostics["import_non_mdns_or_unsupported"] = unsupported
            staged.diagnostics["import_decode_errors"] = decode_errors
            self.an=staged
            # Imported captures can be hidden by a persisted ERSPAN-only filter.
            # Show the complete newly imported dataset instead of leaving the
            # dashboard and packet count at zero for local PCAP traffic.
            all_sources_index = self.source_filter.findData("all")
            if all_sources_index >= 0 and self.source_filter.currentIndex() != all_sources_index:
                self.source_filter.setCurrentIndex(all_sources_index)
            # Active browse results belong to the previous observation context.
            self.active_results.clear(); self.discovery_events.clear(); self._comparison_data=[]; self._comparison_cache_key=None
            self.refresh(); self.refresh_discovery(); self.refresh_comparison_if_visible()
            self.bus.status.emit(f"Imported {frames:,} frames · {mdns:,} mDNS packets · All sources shown · {Path(path).name}")
        except Exception as e:
            QMessageBox.critical(self,"Import failed",str(e)); self.bus.status.emit("Import failed: "+str(e))
        finally: QApplication.restoreOverrideCursor()
    def clear_session(self):
        if self.capture and self.capture.is_alive(): QMessageBox.information(self,"Capture active","Stop the live capture before clearing the session."); return
        self.an.clear(); self.active_results.clear(); self.discovery_events.clear(); self._comparison_data=[]; self._comparison_cache_key=None; self.refresh_discovery(); self.fill_table(self.compare_table, []); self.refresh(); self.bus.status.emit("Session cleared")
    def set_persistent_row_filter(self, table, predicate, description=""):
        """Apply and retain a semantic row filter across live table rebuilds."""
        if not hasattr(self, "_persistent_row_filters"):
            self._persistent_row_filters = {}
        previous=self._persistent_row_filters.get(table)
        if previous is None or previous[1] != description:
            page_index=self.tabs.indexOf(table.parentWidget()) if hasattr(self,"tabs") else -1
            self._drilldown_history.append((table,previous,page_index))
        self._persistent_row_filters[table] = (predicate, description)
        self.apply_persistent_row_filter(table)
        self.update_drilldown_banner()

    def clear_persistent_row_filter(self, table):
        if hasattr(self, "_persistent_row_filters"):
            self._persistent_row_filters.pop(table, None)
        for row in range(table.rowCount()):
            table.setRowHidden(row, False)
        if hasattr(self, "table_filter") and self.current_filter_table() is table:
            self.apply_current_table_filter(self.table_filter.text())
        self.update_drilldown_banner()

    def update_drilldown_banner(self, *_):
        filters=getattr(self,"_persistent_row_filters",{})
        if not filters:
            self.drilldown_bar.hide()
            self.drilldown_back_btn.setEnabled(bool(getattr(self,"_drilldown_history",[])))
            self.drilldown_clear_btn.setEnabled(False)
            return
        current_table=self.current_filter_table() if hasattr(self,"tabs") else None
        latest_table=getattr(self,"_drilldown_history",[])[-1][0] if getattr(self,"_drilldown_history",[]) else None
        chosen_table=current_table if current_table in filters else (latest_table if latest_table in filters else next(reversed(filters)))
        description=filters[chosen_table][1] or "Filtered view"
        page_index=self.tabs.indexOf(chosen_table.parentWidget()) if hasattr(self,"tabs") else -1
        page_name=self.tabs.tabText(page_index) if page_index>=0 else "workspace"
        if chosen_table is current_table:
            visible=sum(not chosen_table.isRowHidden(row) for row in range(chosen_table.rowCount()))
            text=f"Drill-down: {description} · {visible:,} matching rows in {page_name}."
        else:
            text=f"Drill-down active in {page_name}: {description}. Select that workspace to view the matching rows."
        other_filters=len(filters)-1
        if other_filters>0: text+=f" Plus {other_filters} other filtered view{'s' if other_filters!=1 else ''}."
        self.drilldown_status.setText(text)
        self.drilldown_back_btn.setEnabled(bool(getattr(self,"_drilldown_history",[])))
        self.drilldown_clear_btn.setEnabled(True)
        self.drilldown_bar.show()

    def back_drilldown(self):
        history=getattr(self,"_drilldown_history",[])
        if not history: return
        table,previous,page_index=history.pop()
        if page_index>=0: self.tabs.setCurrentIndex(page_index)
        if previous is None:
            self._persistent_row_filters.pop(table,None)
            for row in range(table.rowCount()): table.setRowHidden(row,False)
        else:
            self._persistent_row_filters[table]=previous
            self.apply_persistent_row_filter(table)
        if self.current_filter_table() is table:
            self.apply_current_table_filter(self.table_filter.text())
        self.update_drilldown_banner()
        self.bus.status.emit("Returned to the previous drill-down")

    def apply_persistent_row_filter(self, table):
        entry = getattr(self, "_persistent_row_filters", {}).get(table)
        if not entry:
            return
        predicate, _description = entry
        table.setUpdatesEnabled(False)
        for row in range(table.rowCount()):
            cells = [table.item(row, col).text() if table.item(row, col) else "" for col in range(table.columnCount())]
            try:
                visible = bool(predicate(cells))
            except Exception:
                visible = True
            table.setRowHidden(row, not visible)
        table.setUpdatesEnabled(True)
        if hasattr(self, "table_filter") and self.current_filter_table() is table and self.table_filter.text().strip():
            self.apply_current_table_filter(self.table_filter.text())

    def fill_table(self,t,rows):
        t.setUpdatesEnabled(False)
        t.setSortingEnabled(False)
        t.setRowCount(len(rows))
        headers=[t.horizontalHeaderItem(c).text().lower() if t.horizontalHeaderItem(c) else "" for c in range(t.columnCount())]
        for r,row in enumerate(rows):
            for c,val in enumerate(row):
                text=str(val); item=SortableTableWidgetItem(text); item.setToolTip(text)
                h=headers[c] if c < len(headers) else ""
                # Semantic status colors are restrained and consistent across all inventory tables.
                if any(k in h for k in ("status","health","interpretation","assessment")):
                    low=text.lower()
                    if any(k in low for k in ("conflict","error","incomplete","failed","missing","unresolved")):
                        item.setForeground(QBrush(QColor("#ff7777")))
                    elif any(k in low for k in ("complete","resolved","match","both methods","healthy","ok")):
                        item.setForeground(QBrush(QColor("#62d6a5")))
                    elif low in {"yes","active","passive only","active only"}:
                        item.setForeground(QBrush(QColor("#f5c36a" if low.endswith("only") else "#62d6a5")))
                    elif low in {"no","unknown","not observed"}:
                        item.setForeground(QBrush(QColor("#9aa9bb")))
                if h == "conflicts" and text.strip(): item.setForeground(QBrush(QColor("#ff7777")))
                t.setItem(r,c,item)
            t.setRowHidden(r,False)
        t.setUpdatesEnabled(True)
        t.setSortingEnabled(True)
        self.apply_persistent_row_filter(t)
        if hasattr(self,"table_filter") and self.current_filter_table() is t: self.apply_current_table_filter(self.table_filter.text())
    def save_table_widths(self, table, key):
        if not hasattr(self,"settings"): return
        widths=[table.columnWidth(i) for i in range(table.columnCount())]
        self.settings.setValue(key,widths)

    def current_filter_table(self):
        # currentChanged can fire while tabs are still being constructed. Resolve
        # widgets lazily instead of evaluating every self.<table> attribute up front.
        idx = self.tabs.currentIndex()
        table_names = {
            1: "packet_table", 2: "device_table", 3: "service_table",
            4: "group_table", 6: "active_table", 7: "compare_table",
            8: "catalog_table", 9: "rule_results", 10: None,
            11: "chain_table", 12: "flow_table", 13: "investigation_findings",
        }
        name = table_names.get(idx)
        return getattr(self, name, None) if name else None

    def restore_current_table_filter(self, *_):
        idx=self.tabs.currentIndex(); value=self.settings.value(f"tableFilters/{idx}","")
        self.table_filter.blockSignals(True); self.table_filter.setText(str(value or "")); self.table_filter.blockSignals(False)
        self.apply_current_table_filter(self.table_filter.text())

    def apply_current_table_filter(self, text):
        idx=self.tabs.currentIndex(); self.settings.setValue(f"tableFilters/{idx}",text)
        table=self.current_filter_table()
        if table is None: return
        needle=str(text).strip().casefold()
        table.setUpdatesEnabled(False)
        persistent = getattr(self, "_persistent_row_filters", {}).get(table)
        predicate = persistent[0] if persistent else None
        for row in range(table.rowCount()):
            cells = [table.item(row, col).text() if table.item(row, col) else "" for col in range(table.columnCount())]
            text_match = (not needle) or any(needle in cell.casefold() for cell in cells)
            try:
                drilldown_match = bool(predicate(cells)) if predicate else True
            except Exception:
                drilldown_match = True
            table.setRowHidden(row, not (text_match and drilldown_match))
        table.setUpdatesEnabled(True)
        self.update_drilldown_banner()

    def _refresh_flow_filter_choices(self, packets):
        import ipaddress
        groups=set(); types=set()
        for packet in packets:
            dst=str(packet.get("destination") or "")
            try:
                if ipaddress.ip_address(dst).is_multicast: groups.add(dst)
            except ValueError: pass
            types.update(packet_service_types(packet))
        for widget, values, default in ((self.flow_group_filter,sorted(groups),"All groups"),(self.flow_service_filter,sorted(types),"All service types")):
            current=widget.currentText(); widget.blockSignals(True); widget.clear(); widget.addItem(default)
            for value in values: widget.addItem(value)
            ix=widget.findText(current)
            widget.setCurrentIndex(ix if ix>=0 else 0); widget.blockSignals(False)

    def _hostname_map(self, devices=None):
        """Return IP-to-hostname labels from passive packet-derived device evidence."""
        if devices is None:
            try:
                devices = self.an.snapshot(include_packets=False).get("devices", [])
            except Exception:
                devices = []
        result = {}
        for device in devices or []:
            ip = str(device.get("ip") or "")
            names = device.get("hostnames", []) or []
            if ip and names:
                result[ip] = ", ".join(sorted({str(name) for name in names if name}))
        return result

    def _hostname_for(self, ip, hostname_map):
        return hostname_map.get(str(ip or ""), "—")

    def _endpoint_label(self, address, hostname_map):
        """Prefer a learned hostname while retaining the address for exact identification."""
        address = str(address or "").strip()
        if not address:
            return "—"
        hostname = hostname_map.get(address)
        if not hostname or hostname == "—":
            return address
        # The map may contain multiple observed names for one address.
        return f"{hostname} ({address})"

    def _finding_subject_label(self, finding, hostname_map):
        subject = str(finding.get("subject") or "")
        if subject in hostname_map:
            return self._endpoint_label(subject, hostname_map)
        # Preserve service-instance names and other non-IP subjects unchanged.
        return subject

    def refresh_flow_view(self, *_):
        if not hasattr(self,"flow_table"): return
        packets=filter_flow_packets(
            getattr(self,"_flow_packets_cache",[]),
            ip_filter=self.flow_ip_filter.text(),
            multicast_group=self.flow_group_filter.currentText(),
            service_type=self.flow_service_filter.currentText(),
            minutes={"Last 1 minute":1,"Last 5 minutes":5,"Last 15 minutes":15,"Last hour":60}.get(self.flow_time_filter.currentText()),
        )
        data=build_flow_summary(packets)
        hostnames = self._hostname_map()
        flow_rows = [[self._endpoint_label(row[0], hostnames),
                      self._endpoint_label(row[1], hostnames) if row[1] not in ("224.0.0.251", "ff02::fb") else row[1],
                      *list(row[2:])] for row in data["rows"]]
        self.conversation_map.set_rows(data["rows"], hostnames); self.fill_table(self.flow_table,flow_rows)
        self.flow_summary.setText(f"{len(data['rows']):,} observed conversations · {len(packets):,} packets match filters · time window is relative to newest packet in this capture")

    def reset_flow_filters(self):
        self.flow_ip_filter.clear(); self.flow_group_filter.setCurrentIndex(0); self.flow_service_filter.setCurrentIndex(0); self.flow_time_filter.setCurrentIndex(0)

    def flow_edge_selected(self, source, destination):
        """Open packet evidence for the exact observed source/destination pair."""
        self.refresh()
        self.tabs.setCurrentWidget(self.packet_table)
        self.set_persistent_row_filter(self.packet_table, lambda cells: cells[3] == source and cells[4] == destination, f"Flow edge: {source} → {destination}")
        self.bus.status.emit(f"Packet evidence: {source} → {destination}")

    def flow_chart_drilldown(self,label,category):
        self.tabs.setCurrentWidget(self.flow_table); self.table_filter.setText(str(label))

    def flow_destination_drilldown(self,label,category):
        self.tabs.setCurrentWidget(self.flow_table); self.table_filter.setText(str(label))

    def _show_packet_indices(self, indices, label):
        self.refresh()
        packets=list(self.an.packets)
        wanted=[]
        for idx in indices:
            try:
                packet=packets[int(idx)]
                wanted.append((str(packet.get("time", "")).split("T")[-1], str(packet.get("direction", "")),
                               str(packet.get("source", "")), str(packet.get("destination", "")),
                               self.packet_summary(packet)))
            except (IndexError, TypeError, ValueError):
                continue
        self.tabs.setCurrentWidget(self.packet_table)
        for row in range(self.packet_table.rowCount()):
            cells=[self.packet_table.item(row,c).text() if self.packet_table.item(row,c) else "" for c in range(self.packet_table.columnCount())]
            visible=any(cells[0]==key[0] and cells[1]==key[1] and cells[3]==key[2] and cells[4]==key[3] and key[4] in cells[6] for key in wanted)
            self.packet_table.setRowHidden(row, not visible)
        self.bus.status.emit(label)

    def investigation_correlation_selected(self, row, _column=0):
        candidates=getattr(self, "_investigation_correlations", [])
        if row < 0 or row >= len(candidates): return
        item=candidates[row]
        self._show_packet_indices([item.get("query_index",-1), item.get("response_index",-1)],
                                  f"Candidate query/response evidence: {item.get('name','')} · correlation is heuristic")

    def investigation_finding_selected(self, row, _column=0):
        if row < 0: return
        subject=self.investigation_findings.item(row,2)
        if not subject: return
        value=subject.text().strip()
        if not value: return
        self.tabs.setCurrentWidget(self.packet_table)
        needle=value.casefold()
        self.set_persistent_row_filter(self.packet_table, lambda cells: needle in " ".join(cells).casefold(), f"Finding evidence: {value}")
        self.bus.status.emit(f"Finding evidence filter: {value}")

    def service_chain_selected(self, row, _column=0):
        if row < 0: return
        instance=self.chain_table.item(row,0)
        if not instance: return
        self.selected_service_packets_for_instance(instance.text())

    def selected_service_packets_for_instance(self, instance):
        self.refresh()
        needle=str(instance).casefold()
        self.tabs.setCurrentWidget(self.packet_table)
        self.set_persistent_row_filter(self.packet_table, lambda cells: needle in cells[6].casefold(), f"Service packet evidence: {instance}")
        self.bus.status.emit(f"Service packet evidence: {instance}")

    def schedule_refresh(self, *_):
        self.refresh_debounce.start(250)
    def on_tab_changed(self, *_):
        if self.tabs.currentWidget() is self.active_table.parentWidget():
            self._discovery_dirty=True
            self.refresh_discovery()
        self.refresh()

    def _workspace_selected(self, picker_index):
        if picker_index >= 0:
            self.tabs.setCurrentIndex(int(self.workspace_picker.itemData(picker_index)))

    def _workspace_changed(self, tab_index):
        if tab_index >= 0:
            picker_index = self.workspace_picker.findData(tab_index)
            if picker_index >= 0 and picker_index != self.workspace_picker.currentIndex():
                self.workspace_picker.blockSignals(True)
                self.workspace_picker.setCurrentIndex(picker_index)
                self.workspace_picker.blockSignals(False)

    def run_guided_troubleshooting(self):
        snap = self.an.snapshot(include_packets=True)
        packets = snap.get("packets", [])
        result = analyze_guided_issue(packets, self.guided_symptom.currentData(), self.guided_service.text(), self.guided_client.text())
        ranked = rank_likely_causes(packets, self.guided_symptom.currentData(), self.guided_service.text(), self.guided_client.text())
        esc = lambda value: html.escape(str(value))
        sections = []
        for step in result["steps"]:
            sections.append(f'<section style="background:#19222e;border:1px solid #2b394b;border-radius:10px;padding:13px;margin:0 0 10px"><h3 style="color:#ff9858;margin:0 0 6px">{esc(step["title"])}</h3><p><b>{esc(step["status"])}</b> · {esc(step["confidence"])}</p><p><b>Evidence:</b> {esc(step["evidence"])}</p><p><b>Next check:</b> {esc(step["action"])}</p></section>')
        sections.append(f'<p style="color:#aab7c7"><b>Limit:</b> {esc(result["caveat"])}</p>')
        self.guided_plan_text.setHtml('<html><body style="font-family:-apple-system,Arial;color:#e9eef5;background:#141c26;font-size:14px;line-height:1.5">' + ''.join(sections) + '</body></html>')
        self.guided_summary.setText(f"Analyzed {result['packet_total']:,} retained packet(s); {result['matched_count']:,} matched the filters. Evidence references use packet indices from the current retained history. Ranked causes are heuristic priorities, not probabilities.")
        self._guided_cause_indices = [x["evidence_indices"] for x in ranked["causes"]]
        cause_rows = [[x["rank"], x["cause"], f"{x['score']}/100", x["supports"], x["weakens"], x["next_test"]] for x in ranked["causes"]]
        self.fill_table(self.guided_causes_table, cause_rows)
        hostnames = self._hostname_map(snap.get("devices", []))
        rows = [[x["index"], x.get("time", ""), x.get("direction", ""), self._endpoint_label(x.get("source", ""), hostnames), self._endpoint_label(x.get("destination", ""), hostnames), x.get("summary", "")] for x in result["evidence"]]
        self.fill_table(self.guided_evidence_table, rows)
        self._guided_evidence_indices = [x["index"] for x in result["evidence"]]
        self.bus.status.emit("Guided troubleshooting plan built from retained packet evidence")

    def guided_cause_selected(self, row, _column=0):
        """Open packet evidence supporting the selected ranked hypothesis."""
        indices = getattr(self, "_guided_cause_indices", [])
        if 0 <= row < len(indices) and indices[row]:
            self._show_packet_indices(indices[row], "Ranked troubleshooting cause · supporting packet evidence")
        else:
            self.bus.status.emit("No matching packet evidence is retained for this hypothesis; run the suggested next test")

    def guided_evidence_selected(self, row, _column=0):
        item = self.guided_evidence_table.item(row, 0)
        if item is None:
            return
        try:
            index = int(item.text())
        except ValueError:
            return
        self._show_packet_indices([index], f"Guided troubleshooting evidence · packet index {index}")

    def refresh_temporal_analytics(self):
        """Analyze repeated discovery activity in capture-relative time windows."""
        snap = self.an.snapshot(include_packets=True)
        packets = snap.get("packets", [])
        result = analyze_temporal_discovery(packets)
        self._temporal_pattern_indices = [row.get("evidence_indices", []) for row in result.get("patterns", [])]
        if not result.get("available"):
            self.temporal_summary.setText("Temporal analysis is unavailable: " + result.get("reason", "no usable timestamps"))
            self.fill_table(self.temporal_table, [])
            self.bus.status.emit("Temporal analytics unavailable: no parseable timestamps")
            return
        summary = result["summary"]
        self.temporal_summary.setText(
            f"{summary['queries']} query observations · {summary['candidate_answered']} with a matching response candidate · "
            f"{summary['no_candidate']} with no matching response observed · {summary['time_windows']} time window(s). "
            "A candidate is not proof of delivery or application success; repeated across windows is stronger evidence than a single burst."
        )
        rows = []
        for pattern in result.get("patterns", []):
            hostnames = self._hostname_map(snap.get("devices", []))
            rows.append([pattern["classification"], f"{pattern['name']} ({pattern['type']})", self._endpoint_label(pattern["source"], hostnames),
                         pattern["query_count"], pattern["candidate_answered"], pattern["windows_seen"],
                         ", ".join(str(i) for i in pattern["evidence_indices"][:12]) + ("…" if len(pattern["evidence_indices"]) > 12 else ""), self._hostname_for(pattern.get("source"), hostnames)])
        self.fill_table(self.temporal_table, rows)
        self._temporal_result = result
        self.bus.status.emit("Temporal discovery analytics refreshed from retained packet evidence")

    def temporal_pattern_selected(self, row, _column=0):
        indices = getattr(self, "_temporal_pattern_indices", [])
        if 0 <= row < len(indices) and indices[row]:
            self._show_packet_indices(indices[row], "Temporal discovery pattern · supporting packet evidence")
        else:
            self.bus.status.emit("No packet evidence retained for this temporal pattern")

    def refresh_plain_language_insights(self):
        s = self.an.snapshot(include_packets=True)
        self.insights_text.setHtml(self.build_plain_language_insights(s))
        self.refresh_temporal_analytics()
        self.bus.status.emit("Plain-language interpretation refreshed")

    def build_plain_language_insights(self, s):
        packets = s.get("packets", [])
        chains = build_service_chains(packets)
        intel = build_traffic_intelligence(packets)
        quality = assess_capture_quality(diagnostics=s.get("diagnostics", {}), packet_count=s.get("packet_count", 0), capture_started=s.get("capture_started"), capture_error=s.get("capture_error", ""), packet_history_truncated=s.get("packet_history_truncated", False))
        esc = lambda value: html.escape(str(value))
        sections = []
        def section(title, body):
            sections.append(f'<section style="background:#19222e;border:1px solid #2b394b;border-radius:10px;padding:14px;margin:0 0 12px"><h2 style="color:#ff9858;margin:0 0 8px">{esc(title)}</h2>{body}</section>')
        n_packets = int(s.get("packet_count", 0)); n_devices = len(s.get("devices", [])); n_services = len(s.get("services", []))
        direction = intel.get("directions", {})
        queries = int(direction.get("Query", 0)); responses = int(direction.get("Response", 0))
        section("At a glance", f'<p>The current session contains <b>{n_packets:,} decoded mDNS packets</b>, with <b>{n_devices}</b> observed source IPs and <b>{n_services}</b> service instances. These are observations from this capture point and time window, not a complete inventory of the network.</p>')
        if not n_packets:
            section("What this means", '<p>No decoded mDNS packets are currently available. This does not by itself mean Bonjour is absent. Start a capture or import a PCAP/PCAPNG, verify the selected interface, and check capture permissions and the capture-quality findings.</p>')
        else:
            ratio = f'{responses / queries:.2f}' if queries else 'not meaningful (no queries observed)'
            section("Query and response activity", f'<p>Observed <b>{queries:,} queries</b> and <b>{responses:,} response packets</b>. The response-to-query packet ratio is {ratio}. Do not interpret this as a success rate: mDNS responses can answer multiple questions, use multicast, and be visible differently at different observation points.</p>')
        if chains:
            complete = sum(1 for c in chains if str(c.get("status", "")).lower().startswith(("complete", "ok")) and not c.get("conflicts"))
            incomplete = len(chains) - complete
            conflict = sum(1 for c in chains if c.get("conflicts"))
            section("Bonjour service records", f'<p>Correlated {len(chains)} service chains across DNS-SD records. {complete} have the expected record relationships in the retained evidence; {incomplete} are incomplete or otherwise need review; {conflict} show record conflicts.</p><p><b>Plain language:</b> a service advertisement usually points to a named service instance, which points to a host and port, with TXT metadata and address records providing more detail. Missing pieces may reflect capture timing or visibility rather than a broken service.</p>')
            problem = [c for c in chains if c.get("conflicts") or str(c.get("status", "")).lower() not in ("complete", "ok")]
            if problem:
                items = ''.join(f'<li><b>{esc(c.get("instance") or c.get("service_type") or "Unknown service")}</b>: {esc("; ".join(c.get("conflicts", [])) or c.get("status", "Incomplete record chain"))}. Observed records: {esc(", ".join(c.get("evidence", [])) or "not recorded")}</li>' for c in problem[:12])
                section("Services worth inspecting", f'<ul>{items}</ul>')
        else:
            # Distinguish total captured mDNS packets from DNS-SD records usable for
            # chain correlation. A high packet count alone does not guarantee PTR/SRV/TXT.
            dns_sd_records = 0
            record_types = Counter()
            for packet in packets:
                for record in packet.get("records", []) or []:
                    rtype = str(record.get("type", "Other")).upper()
                    record_types[rtype] += 1
                    owner = str(record.get("name") or record.get("owner") or "").rstrip(".").lower()
                    is_meta_ptr = rtype == "PTR" and (owner.startswith("_services._dns-sd._udp.local") or owner.startswith("_dns-sd._udp.local"))
                    if rtype in {"PTR", "SRV", "TXT", "A", "AAAA"} and not is_meta_ptr:
                        dns_sd_records += 1
            observed = ", ".join(f"{key}: {value}" for key, value in record_types.most_common()) or "none decoded"
            section("Bonjour service records", f'<p><b>No service-instance chains were correlated.</b> The session contains {n_packets:,} decoded mDNS packets, but no service-instance PTR → SRV/TXT → A/AAAA relationship was found in the retained evidence. DNS-SD records usable for instance correlation (excluding service-type enumeration PTRs): {dns_sd_records:,}. Decoded record types: {esc(observed)}.</p><p>A high packet count can consist mostly of queries, repeated meta-discovery records, or traffic unrelated to service-instance advertisements. Check whether the capture includes service-type PTR advertisements plus the related SRV/TXT and A/AAAA records. The absence of a chain is an evidence gap, not proof that a service is down. Open Live traffic / Mirror capture and inspect decoded record types before concluding that service chains are absent.</p>')
        sources = intel.get("sources", Counter()).most_common(5)
        if sources:
            body = '<p>These sources generated the most mDNS packets. A high count can indicate a busy device or repeated discovery activity, but is not automatically a fault.</p><ul>' + ''.join(f'<li>{esc(ip)} — {count:,} packets</li>' for ip,count in sources) + '</ul>'
            section("Most active sources", body)
        vlan_counts = intel.get("vlans", Counter()).most_common()
        if vlan_counts:
            section("VLAN visibility", '<p>VLAN labels below are based on visible packet tags. Untagged traffic may be normal at an access-port capture point. If a service is not discoverable across VLANs, verify multicast forwarding, gateway/service-reflector design, and policy on the actual network path.</p><p>' + esc(', '.join(f'{k}: {v} packets' for k,v in vlan_counts[:10])) + '</p>')
        q = quality if isinstance(quality, dict) else {}
        q_summary = q.get("summary") or q.get("message") or format_capture_quality(quality)
        section("Capture confidence", f'<p>{esc(q_summary)}</p><p>A quiet capture can mean a quiet network, a short observation window, a wrong interface, or limited packet visibility. Compare similar capture windows and observation points before drawing conclusions.</p>')
        section("How to use these findings", '<ol><li>Start with incomplete or conflicting service chains.</li><li>Open the relevant service and packet evidence to confirm the actual records.</li><li>For suspected cross-VLAN discovery issues, capture on both sides of the expected path.</li><li>Use capture comparison with similar time windows to identify changes.</li></ol><p><b>Important:</b> passive mDNS evidence shows what the capture observed. It cannot prove that a client received a multicast packet, that a service is reachable, or that an absent advertisement means a device is down.</p>')
        return '<html><body style="font-family:-apple-system,Arial;color:#e9eef5;background:#141c26;font-size:14px;line-height:1.5">' + ''.join(sections) + '</body></html>'

    def snapshot_for_source_filter(self, include_packets=True):
        """Build a consistent analyzer snapshot for the selected capture-origin filter."""
        mode = self.source_filter.currentData() if hasattr(self, "source_filter") else "all"
        raw = self.an.snapshot(include_packets=True)
        packets = raw.get("packets", [])
        if mode == "all":
            if not include_packets:
                raw["packets"] = []
            return raw
        def origin(packet):
            value = packet.get("capture_origin")
            if value in ("local", "erspan"):
                return value
            # Older sessions called capture method/source types "live" and "pcap".
            return "local" if value in (None, "live", "pcap") else value
        chosen = [p for p in packets if origin(p) == mode]
        filtered = Analyzer()
        filtered.started = raw.get("capture_started")
        for packet in chosen:
            filtered.ingest_decoded(dict(packet))
        snap = filtered.snapshot(include_packets=include_packets)
        snap["capture_error"] = raw.get("capture_error", "")
        snap["diagnostics"] = dict(raw.get("diagnostics", {}))
        snap["source_filter"] = mode
        snap["all_packet_count"] = raw.get("packet_count", len(packets))
        return snap

    def refresh(self, *_):
        # Keep the UI responsive: only build expensive content for the selected tab.
        idx=self.tabs.currentIndex()
        dashboard_filter=self.dashboard.filter_text.text().strip().lower() if idx==0 else ""
        dashboard_range=self.dashboard.time_range.currentText() if idx==0 else ""
        with self.an.lock:
            current_revision=self.an.revision
        source_mode = self.source_filter.currentData() if hasattr(self, "source_filter") else "all"
        active_signature=(len(self.active_results),len(self.discovery_events),
            tuple(sorted((str(x.get("service_type","")),str(x.get("status","")),bool(x.get("active",True)),bool(x.get("resolved"))) for x in self.active_results.values())),
            sum(1 for x in self.discovery_events if x.get("event") in ("error","resolve_error")))
        dashboard_signature=(current_revision,dashboard_filter,dashboard_range,active_signature,source_mode)
        update_dashboard=(idx==0 and dashboard_signature!=self._dashboard_signature)
        need_packets = idx in (1,10,11,12,15) or update_dashboard
        s=self.snapshot_for_source_filter(include_packets=need_packets)
        if update_dashboard:
            s["packets"] = (s.get("packets", [])[-self.dashboard.CHART_WINDOW:] if source_mode != "all" else self.an.recent_packets(self.dashboard.CHART_WINDOW))
            if source_mode == "all":
                s["packet_count"]=self.an.snapshot(include_packets=False)["packet_count"]
        self.metric_labels["packets"].setText(f"{s['packet_count']:,}")
        self.metric_labels["devices"].setText(str(len(s["devices"])))
        self.metric_labels["services"].setText(str(len(s["services"])))
        self.metric_labels["groups"].setText(str(len(s["groups"])))
        if idx==0:
            if update_dashboard:
                self.dashboard.update_snapshot(s, list(self.active_results.values()), self.discovery_events)
                self._dashboard_signature=dashboard_signature
        elif idx==1:
            marker=(s.get("revision",0),)
            if self._tab_render_signatures.get(idx)!=marker:
                packets=s["packets"][-500:][::-1]
                hostnames = self._hostname_map(s.get("devices", []))
                self.fill_table(self.packet_table,[[p["time"].split("T")[-1],p["direction"],"ERSPAN" if p.get("capture_origin")=="erspan" else "Local",p["source"],p["destination"],p["vlan"],self.packet_summary(p),p["bytes"],self._hostname_for(p["source"], hostnames),self._hostname_for(p["destination"], hostnames)] for p in packets]); self._tab_render_signatures[idx]=marker
        elif idx==2:
            marker=(s.get("revision",0),)
            if self._tab_render_signatures.get(idx)!=marker:
                ordered_devices=sorted(s["devices"],key=lambda x:x["packets"],reverse=True)
                self.device_top_sources.set_data([(d["ip"],d["packets"]) for d in ordered_devices[:10]])
                vlan_counts=Counter(str(d.get("vlan") or "Unknown") for d in s["devices"])
                self.device_vlan_chart.set_data(vlan_counts.most_common(8))
                self.fill_table(self.device_table,[[self._endpoint_label(d["ip"], {d["ip"]: ", ".join(d["hostnames"])} if d.get("hostnames") else {}),d["mac"],d["vlan"],d["packets"],d["queries"],d["responses"],", ".join(d["hostnames"]),", ".join(d["services"]),d["last_seen"]] for d in ordered_devices]); self._tab_render_signatures[idx]=marker
                self.update_device_health()
        elif idx==3:
            marker=(s.get("revision",0),)
            if self._tab_render_signatures.get(idx)!=marker:
                services=sorted(s["services"],key=lambda x:x["records"],reverse=True)
                chains=build_service_chains(s.get("packets",[]))
                self.service_kpi_labels["instances"].setText(str(len(services)))
                self.service_kpi_labels["types"].setText(str(len({x.get("service_type","") for x in services if x.get("service_type")})))
                self.service_kpi_labels["resolved"].setText(str(sum(bool(x.get("target")) for x in services)))
                issues=sum(1 for x in chains if x.get("status","").lower() not in {"complete","ok"} or x.get("conflicts"))
                self.service_kpi_labels["issues"].setText(str(issues))
                self.service_type_chart.set_data(Counter(x.get("service_type") or "Unknown" for x in services).most_common(8))
                health=Counter(("Conflicts" if x.get("conflicts") else x.get("status") or "Unknown") for x in chains)
                self.service_health_chart.set_data(health.most_common(6))
                hostnames = self._hostname_map(s.get("devices", []))
                self._service_inventory={str(x.get("instance","")):x for x in services}
                self.fill_table(self.service_table,[[x["instance"],x["service_type"],self._endpoint_label(x["target"], hostnames),x["port"]," | ".join(x["txt"]),", ".join(self._endpoint_label(src, hostnames) for src in x["sources"]),x["last_seen"],", ".join(sorted({hostnames[src] for src in x["sources"] if src in hostnames})) or "—"] for x in services])
                for row in range(self.service_table.rowCount()):
                    instance_item=self.service_table.item(row,0)
                    service=self._service_inventory.get(instance_item.text()) if instance_item else None
                    if not service: continue
                    type_item=self.service_table.item(row,1)
                    catalog=self.service_catalog_entry(service.get("service_type"))
                    purpose=catalog.get("description") or "No catalog description; select Explain selected service for observed evidence and guidance."
                    if type_item: type_item.setToolTip(f"{service.get('service_type','Unknown')}\n\n{catalog.get('name','Service type')}\n{purpose}")
                self.update_service_explanation_action(); self._tab_render_signatures[idx]=marker
        elif idx==4:
            marker=(s.get("revision",0),)
            if self._tab_render_signatures.get(idx)!=marker:
                total=max(1,s["packet_count"]); self.fill_table(self.group_table,[[g,n,f"{n/total:.1%}"] for g,n in sorted(s["groups"].items(),key=lambda x:x[1],reverse=True)]); self._tab_render_signatures[idx]=marker
        elif idx==5:
            s["discovery_diagnostics"] = summarize_discovery_events(self.discovery_events)
            marker=(s["packet_count"],len(s["devices"]),len(s["services"]),len(self.discovery_events))
            if getattr(self,"_findings_marker",None)!=marker:
                self.report_text.setPlainText(self.findings(s)); self._findings_marker=marker
        elif idx==6:
            self.refresh_discovery()
        elif idx==7:
            self.refresh_comparison()
        elif idx==10:
            marker=(s.get("revision",0),)
            # Rebuild only when packet evidence changes; active discovery does not invalidate passive analysis.
            if self._tab_render_signatures.get(idx)==marker:
                return
            intel=build_traffic_intelligence(s["packets"])
            lines=["TRAFFIC OVERVIEW", f"mDNS packets in session: {s['packet_count']:,}",
                   f"Queries: {intel['directions'].get('Query',0):,}   Responses: {intel['directions'].get('Response',0):,}",
                   "", "ADDRESS FAMILY", *[f"• {k}: {v}" for k,v in intel['families'].most_common()],
                   "", "TOP SOURCES", *[f"• {k}: {v} packets" for k,v in intel['sources'].most_common(12)],
                   "", "VLAN EVIDENCE", *[f"• VLAN {k}: {v} packets" for k,v in intel['vlans'].most_common(12)],
                   "", "BUSIEST MINUTES (based on packet timestamps)", *[f"• {k}: {v} packets" for k,v in intel['minute_bins'].most_common(12)],
                   "", "REPEATED QUERY CANDIDATES", "Repeated question names with no same-name/type response record in this capture. This intentionally conservative heuristic can miss valid PTR-to-instance responses and is not proof of unanswered DNS requests."]
            if intel['candidate_queries']:
                lines += [f"• {name} [{typ}] — {count} queries; no matching response record observed" for name,typ,count in sorted(intel['candidate_queries'], key=lambda x:x[2], reverse=True)[:30]]
            else:
                lines.append("• No candidates under this heuristic.")
            self.traffic_intel_text.setPlainText("\n".join(lines)); self._tab_render_signatures[idx]=marker
        elif idx==11:
            marker=(s.get("revision",0),)
            if self._tab_render_signatures.get(idx)!=marker:
                chains=build_service_chains(s.get("packets",[]))
                hostnames = self._hostname_map(s.get("devices", []))
                self.fill_table(self.chain_table,[[x["instance"],x["service_type"],self._endpoint_label(x["target"], hostnames),x["port"],", ".join(self._endpoint_label(address, hostnames) for address in x["addresses"])," | ".join(x["txt"]),", ".join(x["evidence"]),", ".join(self._endpoint_label(src, hostnames) for src in x["sources"]),x["status"],"; ".join(x.get("conflicts",[])),", ".join(sorted({hostnames[address] for address in x["addresses"] if address in hostnames})) or "—"] for x in chains]); self._tab_render_signatures[idx]=marker
        elif idx==12:
            marker=(s.get("revision",0),)
            if self._tab_render_signatures.get(idx)!=marker:
                self._flow_packets_cache=list(s.get("packets",[]))
                self._flow_revision=s.get("revision",0)
                self._refresh_flow_filter_choices(self._flow_packets_cache)
                self.refresh_flow_view()
                self._tab_render_signatures[idx]=marker
        elif idx==13:
            marker=(s.get("revision",0), len(self.discovery_events))
            if self._tab_render_signatures.get(idx)!=marker:
                chains=build_service_chains(s.get("packets",[]))
                investigation=build_investigation(s.get("packets",[]), chains, s.get("devices",[]))
                self._investigation_correlations=investigation["query_response_candidates"]
                self.fill_table(self.investigation_timeline,[[x["offset_seconds"],x["packets"],x["queries"],x["responses"],x["sources"]] for x in investigation["timeline"]])
                self.fill_table(self.investigation_findings,[[x["priority"],x["finding"],self._finding_subject_label(x, hostnames),x["evidence"],x["action"]] for x in investigation["findings"]])
                hostnames = self._hostname_map(s.get("devices", []))
                self.fill_table(self.investigation_correlations,[[x["name"],x["type"],self._endpoint_label(x["source"], hostnames),self._endpoint_label(x["responder"], hostnames),x["delta_seconds"],x["confidence"],x["evidence"]] for x in investigation["query_response_candidates"]])
                self._tab_render_signatures[idx]=marker
        elif idx==15:
            marker=(s.get("revision",0), len(self.discovery_events))
            if self._tab_render_signatures.get(idx)!=marker:
                self.insights_text.setHtml(self.build_plain_language_insights(s))
                self._tab_render_signatures[idx]=marker
        # Static catalog and VLAN planner aren't rebuilt on every capture tick.
        # Re-apply the active drill-down after live refreshes rebuild tables; otherwise
        # fill_table() unhides every row and makes the selection appear to disappear.
        self.apply_dashboard_drilldown_visibility()

    def apply_dashboard_drilldown_visibility(self):
        if not self.dashboard.drilldown_value:
            return
        label = self.dashboard.drilldown_value.strip().casefold()
        category = self.dashboard.drilldown_category
        table = self.device_table if category == "source" else (self.active_table if category == "resolution_state" else (self.service_table if category in ("active_type", "service_type", "active") else (self.packet_table if category in ("destination", "record_type", "time_bucket", "health") else self.packet_table)))
        if table not in self._persistent_row_filters:
            self.set_persistent_row_filter(table, lambda cells: label in " ".join(cells).casefold(), f"Dashboard: {label}")
        else:
            self.apply_persistent_row_filter(table)

    def dashboard_drilldown(self,label,category):
        label=str(label); category=str(category)
        display_label=label
        target_label=getattr(self.dashboard,"drilldown_targets",{}).get(label,label) if category=="source" else label
        self.dashboard.filter_text.setText(target_label)
        if category=="source":
            detail=f"DRILL-DOWN · Source device: {display_label}. Passive traffic charts use the IP filter; active Bonjour discovery charts are independent."
            table=self.device_table
            table_label="source device"
        elif category == "resolution_state":
            detail=f"DRILL-DOWN · Resolution health: {label}. Showing matching active Bonjour discovery results."
            table=self.active_table
            table_label="active discovery resolution state"
        elif category in ("active_type","service_type","active"):
            detail=f"DRILL-DOWN · Bonjour service type: {label}. This selection comes from active discovery; passive packet charts are not a direct view of these browse results."
            table=self.service_table
            table_label="service type"
        elif category == "record_type":
            detail=f"DRILL-DOWN · DNS record mix: {label}. Showing packet evidence matching this record/query type."; table=self.packet_table; table_label="DNS record type"
        elif category == "time_bucket":
            detail=f"DRILL-DOWN · Traffic time bucket: {label}. Showing packets from the selected minute where timestamps are available."; table=self.packet_table; table_label="traffic time bucket"
        else:
            detail=f"DRILL-DOWN · Destination / value: {display_label}. Showing matching packet evidence."
            table=self.packet_table
            table_label="destination / packet value"
        self.dashboard.set_drilldown(display_label,category,detail)
        # Keep the dashboard visible after every chart click, including live
        # traffic time buckets, so the active drill-down context and Clear
        # button remain immediately accessible. Users can open matching packet
        # evidence explicitly from the dashboard banner.
        self.tabs.setCurrentWidget(self.dashboard)
        needle=target_label.casefold()
        if category == "resolution_state":
            predicate=lambda cells: needle in " ".join(cells).casefold()
        elif category == "time_bucket":
            predicate=lambda cells: needle in " ".join(cells).casefold()
        else:
            predicate=lambda cells: needle in " ".join(cells).casefold()
        self.set_persistent_row_filter(table, predicate, f"Dashboard: {display_label}")
        self.bus.status.emit(f"Dashboard drill-down ({table_label}): {label}")

    def clear_all_workspace_drilldowns(self):
        self.dashboard.clear_drilldown()
        self._drilldown_history.clear()
        for table in list(getattr(self, "_persistent_row_filters", {}).keys()):
            self.clear_persistent_row_filter(table)
        self.bus.status.emit("Workspace drill-down filters cleared")

    def clear_dashboard_drilldown(self):
        self.clear_all_workspace_drilldowns()

    @staticmethod
    def packet_summary(p):
        parts=[f"{q['name']} {q['type']}" for q in p["questions"][:3]]+[f"{r['type']} {r['name']}" for r in p["records"][:3]]
        return "; ".join(parts) or "mDNS"
    def findings(self,s):
        out=["SESSION SUMMARY",f"Generated: {s['generated_at']}",f"Capture started: {s['capture_started'] or 'not recorded'}",f"mDNS packets: {s['packet_count']}",f"Unique source IPs: {len(s['devices'])}",f"Service instances: {len(s['services'])}","", "TOP SOURCES"]
        for d in sorted(s['devices'],key=lambda x:x['packets'],reverse=True)[:10]: out.append(f"• {d['ip']} ({d['mac'] or 'MAC unavailable'}) — {d['packets']} packets; {d['queries']} queries / {d['responses']} responses; VLAN {d['vlan']}")
        out += ["", "CAPTURE / DECODER DIAGNOSTICS"]
        out += [f"• {k.replace('_', ' ')}: {v}" for k,v in sorted(s.get("diagnostics", {}).items())] or ["• No frames processed yet"]
        quality = assess_capture_quality(
            diagnostics=s.get("diagnostics", {}), packet_count=s.get("packet_count", 0),
            capture_started=s.get("capture_started"), capture_error=s.get("capture_error", ""),
            packet_history_truncated=s.get("packet_history_truncated", False))
        out += ["", format_capture_quality(quality)]
        if s.get("capture_error"):
            out += ["", "CAPTURE ERROR", s["capture_error"]]
        discovery_diag = s.get("discovery_diagnostics") or summarize_discovery_events(s.get("discovery_events", []))
        if discovery_diag.get("error_count"):
            out += ["", "BONJOUR DISCOVERY WARNINGS", f"Discovery errors recorded: {discovery_diag['error_count']}"]
            for error in discovery_diag.get("recent_errors", [])[-10:]:
                label = error.get("service_type") or error.get("instance") or error.get("event")
                out.append(f"• {error.get('time','')} · {label}: {error.get('error','Unknown error')}")
        elif discovery_diag.get("event_counts"):
            out += ["", "BONJOUR DISCOVERY", f"Events recorded: {sum(discovery_diag['event_counts'].values())}; no discovery errors recorded."]
        if s.get("capture_started") and not s.get("diagnostics", {}).get("frames_seen"):
            out += ["", "LIVE CAPTURE CHECK", "No frames have reached the decoder. Check the selected interface and the operating system's packet-capture backend and permissions. On Windows, verify Npcap is installed. A running status alone does not prove packets are being received."]
        out += ["", "RECORD TYPES"]
        out += [f"• {k}: {v}" for k,v in sorted(s['record_types'].items(),key=lambda x:x[1],reverse=True)] or ["• No records parsed yet"]
        out += ["", "DESTINATIONS"]
        out += [f"• {k}: {v} packets" for k,v in sorted(s['groups'].items(),key=lambda x:x[1],reverse=True)[:10]]
        out += ["", "ENGINEERING NOTES", "• Standard mDNS destinations are 224.0.0.251 (IPv4) and ff02::fb (IPv6).", "• VLAN is shown only when an 802.1Q tag is visible in the capture; mirrored-port configuration can affect this.", "• Active discovery uses Apple Bonjour/DNS-SD browsing; it is separate from passive packet capture.", "• Active browse results may not appear in a passive capture on the same Mac, depending on interface and capture path.", "• A missing response in a capture or browse result is not proof that a service is unavailable."]
        if s["capture_error"]: out += ["", "CAPTURE WARNING", s["capture_error"]]
        if s.get("packet_history_truncated"):
            out += ["", "PACKET HISTORY LIMIT", "The analyzer retained the newest 100,000 mDNS packets. Device counters may include earlier observations; packet-level charts, chains, and exports reflect only retained packet history."]
        out += ["", "ACTIVE BONJOUR DISCOVERY", f"• Active service instances currently tracked: {len(self.active_results)}"]
        for a in sorted(self.active_results.values(),key=lambda x:x.get("service_type",""))[:25]:
            out.append(f"• {a.get('fullname',a.get('instance','unknown'))} — {a.get('host','unresolved')}:{a.get('port','')} — {a.get('status','discovered')}")
        out += ["", "DISCOVERY CORRELATION", f"• Comparison rows: {self.compare_table.rowCount() if hasattr(self, 'compare_table') else 0}"]
        out += ["", "HEALTH & ANOMALY HINTS", "Heuristics only: investigate in context; these are not definitive fault diagnoses."]
        packet_total=max(1,s.get("packet_count",0))
        query_heavy=[d for d in s.get("devices",[]) if d.get("queries",0)>=10 and d.get("queries",0)>=max(1,d.get("responses",0))*4]
        if query_heavy:
            for d in sorted(query_heavy,key=lambda x:x.get("queries",0),reverse=True)[:10]: out.append(f"• Query-heavy source: {d['ip']} — {d['queries']} queries / {d['responses']} responses; check repeated lookups, application retries, or missing responses.")
        else: out.append("• No strongly query-heavy source detected in this session.")
        unresolved=[x for x in s.get("services",[]) if not x.get("target")]
        if unresolved: out.append(f"• {len(unresolved)} service instance(s) lack a correlated SRV target in this capture; capture scope and record timing may explain this.")
        stale=[]
        for d in s.get("devices",[]):
            try:
                age=(datetime.now().astimezone()-datetime.fromisoformat(d.get("last_seen",""))).total_seconds()
                if age>900: stale.append((d,age))
            except Exception: pass
        if stale: out.append(f"• {len(stale)} device(s) have last-seen timestamps over 15 minutes old relative to now; for imported captures, this can be normal.")
        out.append("• A missing observation is not proof that a service is down or that a forwarding rule is broken.")
        return "\n".join(out)
    def export_report(self):
        # Ask for a destination before assembling expensive derived data; cancelling
        # the dialog should not rebuild service chains and traffic summaries.
        path,selected_filter=QFileDialog.getSaveFileName(self,"Export report","mdns-observatory-report.html","HTML report (*.html);;JSON data (*.json);;CSV packets (*.csv);;CSV service chains (*.csv)")
        if not path: return
        try:
            s=build_export_snapshot(
                self.an.snapshot(),
                self.active_results.values(),
                self.discovery_events,
            )
            # Investigation and report sections share the same canonical retained evidence.
            s["investigation"] = build_investigation(s.get("packets", []), s.get("service_chains", []), s.get("devices", []))
            ext=Path(path).suffix.lower()
            if ext==".json":
                with open(path,"w",encoding="utf-8") as f: json.dump(s,f,indent=2,default=list)
            elif ext==".csv":
                with open(path,"w",newline="",encoding="utf-8-sig") as f:
                    if "service chains" in selected_filter.lower():
                        fields=["instance","service_type","target","port","addresses","txt","evidence","sources","status","conflicts","duplicate_observations"]
                        w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
                        for chain in s["service_chains"]:
                            row=dict(chain)
                            for key in ("addresses","txt","evidence","sources","conflicts"): row[key]=" | ".join(map(str,row.get(key,[])))
                            row.pop("record_counts",None); row.pop("ttl_remaining",None)
                            w.writerow({k:row.get(k,"") for k in fields})
                    else:
                        fields=["time","direction","source","destination","mac","vlan","family","sport","dport","questions","records","bytes","source_type"]
                        w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
                        for p in s["packets"]:
                            row={k:p.get(k) for k in fields}; row["questions"]=json.dumps(p["questions"],ensure_ascii=False); row["records"]=json.dumps(p["records"],ensure_ascii=False); w.writerow(row)
            else:
                body=html.escape(self.findings(s)).replace("\n","<br>\n")
                rows="".join(f"<tr><td>{html.escape(d['ip'])}</td><td>{html.escape(d['mac'])}</td><td>{html.escape(d['vlan'])}</td><td>{d['packets']}</td><td>{d['queries']}</td><td>{d['responses']}</td><td>{html.escape(', '.join(d['hostnames']))}</td><td>{html.escape(', '.join(d['services']))}</td></tr>" for d in s["devices"])
                active_rows="".join(f"<tr><td>{html.escape(str(a.get('fullname','')))}</td><td>{html.escape(str(a.get('service_type','')))}</td><td>{html.escape(str(a.get('host','')))}</td><td>{html.escape(str(a.get('port','')))}</td><td>{html.escape(str(a.get('txt','')))}</td><td>{html.escape(str(a.get('status','')))}</td></tr>" for a in s["active_discoveries"])
                compare_rows="".join(f"<tr><td>{html.escape(str(x['service_instance']))}</td><td>{'Yes' if x['passive_seen'] else 'No'}</td><td>{'Yes' if x['active_seen'] else 'No'}</td><td>{html.escape(str(x['target']))}</td><td>{html.escape(str(x['port']))}</td><td>{html.escape(str(x['interpretation']))}</td></tr>" for x in s["comparison"])
                chart_data={
                    "destinations": Counter(p.get("destination") or "unknown" for p in s.get("packets",[])).most_common(8),
                    "record_types": Counter(str(rr.get("type","Other")) for p in s.get("packets",[]) for rr in p.get("records",[])).most_common(8),
                    "top_sources": Counter(p.get("source") or "unknown" for p in s.get("packets",[])).most_common(8),
                }
                def chart_html(title, items):
                    total=max([int(v) for _,v in items]+[1])
                    bars="".join(f'<div class="barrow"><span>{html.escape(str(label))}</span><div class="bartrack"><div class="bar" style="width:{max(1,int(value/total*100))}%"></div></div><span>{value}</span></div>' for label,value in items)
                    return f'<section class="panel"><h2>{html.escape(title)}</h2>{bars or "<p>No data available.</p>"}</section>'
                doc=f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>mDNS Observatory report</title><style>body{{font:15px system-ui;background:#10151d;color:#e9eef5;margin:36px}}h1,h2{{color:#ff9858}}.panel{{background:#19222e;padding:20px;border-radius:12px;margin:18px 0}}.barrow{{display:grid;grid-template-columns:180px 1fr 45px;gap:10px;align-items:center;margin:8px 0;font-size:13px}}.bartrack{{background:#293647;border-radius:5px;height:10px;overflow:hidden}}.bar{{background:#ff914d;height:10px;border-radius:5px}}table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{text-align:left;padding:9px;border-bottom:1px solid #344255}}th{{color:#ffb17f}}pre{{white-space:pre-wrap}}</style></head><body><h1>mDNS Observatory</h1><p>Generated {html.escape(s['generated_at'])} · Passive mDNS analysis</p><p>Stored packet observations: {len(s.get('packets', [])):,}{' · History truncated to newest 100,000 mDNS packets' if s.get('packet_history_truncated') else ''}</p><div class="panel"><pre>{html.escape(self.findings(s))}</pre></div><h2>Bonjour discovery diagnostics</h2><p>Events: {html.escape(json.dumps(s['discovery_diagnostics']['event_counts'], sort_keys=True))} · Errors: {s['discovery_diagnostics']['error_count']}</p><table><thead><tr><th>Time</th><th>Event</th><th>Service</th><th>Error</th></tr></thead><tbody>{''.join(f"<tr><td>{html.escape(str(e.get('time','')))}</td><td>{html.escape(str(e.get('event','')))}</td><td>{html.escape(str(e.get('service_type') or e.get('instance') or ''))}</td><td>{html.escape(str(e.get('error','')))}</td></tr>" for e in s['discovery_diagnostics']['recent_errors']) or '<tr><td colspan="4">No Bonjour errors recorded.</td></tr>'}</tbody></table>{chart_html("Top multicast destinations",chart_data["destinations"])}{chart_html("DNS record mix",chart_data["record_types"])}{chart_html("Top sources",chart_data["top_sources"])}<h2>Device inventory</h2><table><thead><tr><th>IP</th><th>MAC</th><th>VLAN</th><th>Packets</th><th>Queries</th><th>Responses</th><th>Hostnames</th><th>Services</th></tr></thead><tbody>{rows}</tbody></table><h2>Active Bonjour discoveries</h2><table><thead><tr><th>Instance</th><th>Type</th><th>Target</th><th>Port</th><th>TXT</th><th>Status</th></tr></thead><tbody>{active_rows}</tbody></table><h2>Passive vs active comparison</h2><table><thead><tr><th>Service</th><th>Passive</th><th>Active</th><th>Target</th><th>Port</th><th>Interpretation</th></tr></thead><tbody>{compare_rows}</tbody></table><h2>Correlated DNS-SD service chains</h2><table><thead><tr><th>Instance</th><th>Type</th><th>Target</th><th>Port</th><th>Addresses</th><th>Status</th><th>Conflicts</th></tr></thead><tbody>{"".join(f"<tr><td>{html.escape(str(c.get('instance','')))}</td><td>{html.escape(str(c.get('service_type','')))}</td><td>{html.escape(str(c.get('target','')))}</td><td>{html.escape(str(c.get('port','')))}</td><td>{html.escape(', '.join(c.get('addresses',[])))}</td><td>{html.escape(str(c.get('status','')))}</td><td>{html.escape('; '.join(c.get('conflicts',[])))}</td></tr>" for c in s['service_chains'])}</tbody></table><h2>Timeline (capture-relative)</h2><table><thead><tr><th>Offset seconds</th><th>Packets</th><th>Queries</th><th>Responses</th><th>Distinct sources</th></tr></thead><tbody>{"".join(f"<tr><td>{x['offset_seconds']}</td><td>{x['packets']}</td><td>{x['queries']}</td><td>{x['responses']}</td><td>{x['sources']}</td></tr>" for x in s['investigation']['timeline']) or '<tr><td colspan="5">No timestamped packet evidence.</td></tr>'}</tbody></table><h2>Prioritized findings</h2><table><thead><tr><th>Priority</th><th>Finding</th><th>Subject</th><th>Evidence</th><th>Suggested next step</th></tr></thead><tbody>{"".join(f"<tr><td>{html.escape(x['priority'])}</td><td>{html.escape(x['finding'])}</td><td>{html.escape(x['subject'])}</td><td>{html.escape(x['evidence'])}</td><td>{html.escape(x['action'])}</td></tr>" for x in s['investigation']['findings']) or '<tr><td colspan="5">No findings generated.</td></tr>'}</tbody></table><h2>Query / response correlation candidates</h2><p>Candidate correlations are heuristic links based on matching question/record names and timing; they are not proof of causality.</p><table><thead><tr><th>Question</th><th>Type</th><th>Query source</th><th>Candidate responder</th><th>Delta (s)</th><th>Evidence</th></tr></thead><tbody>{"".join(f"<tr><td>{html.escape(x['name'])}</td><td>{html.escape(x['type'])}</td><td>{html.escape(x['source'])}</td><td>{html.escape(x['responder'])}</td><td>{x['delta_seconds']}</td><td>{html.escape(x['evidence'])}</td></tr>" for x in s['investigation']['query_response_candidates']) or '<tr><td colspan="6">No candidate correlations in the retained capture.</td></tr>'}</tbody></table><p>Passive findings include only traffic visible in the selected capture. Active discovery uses macOS Bonjour/DNS-SD. Missing observations do not prove a service is unavailable.</p></body></html>'''
                Path(path).write_text(doc,encoding="utf-8")
            QMessageBox.information(self,"Report exported",f"Saved report to:\n{path}"); self.bus.status.emit("Report exported: "+Path(path).name)
        except Exception as e: QMessageBox.critical(self,"Export failed",str(e))
    def closeEvent(self,event):
        self.an.stop_event.set()
        if self.browser:
            self.browser.stop()
        # Capture and Bonjour workers are daemonized as a final safety net, but
        # request shutdown before allowing the window to close.
        if self.capture and self.capture.is_alive():
            self.capture.join(timeout=1.0)
        event.accept()

def main():
    app=QApplication(sys.argv); app.setApplicationName(APP_NAME); app.setWindowIcon(QIcon(app_icon_path())); app.setFont(QFont("SF Pro Text" if sys.platform == "darwin" else "Segoe UI",10)); w=MainWindow(); w.show(); sys.exit(app.exec())
if __name__=="__main__": main()
