"""DNS-SD service-chain correlation with TTL, duplicate and conflict awareness."""
from collections import defaultdict
import re


def _norm(value):
    return str(value or "").rstrip(".").lower()


def _srv(value):
    """Extract SRV port/target from normalized or Scapy-style RDATA text.

    The decoder has emitted several useful representations across Scapy versions:
    ``port=631 target=printer.local``, ``printer.local:631``, and tuple-like
    ``('printer.local.', 631, 0, 0)``. Accept all of them rather than silently
    leaving a service chain at PTR-only when the SRV record was captured.
    """
    text = str(value or "").strip()
    m = re.search(r"\bport\s*[=:]\s*['\"]?(\d+)", text, re.I)
    t = re.search(r"\btarget\s*[=:]\s*['\"]?([^,;\s'\"]+)", text, re.I)
    if m and t:
        return m.group(1), _norm(t.group(1))
    # Scapy's readable SRV values may put target first as hostname:port.
    m = re.search(r"(?:^|[\s(,])([A-Za-z0-9_.*-]+(?:\.[A-Za-z0-9_.*-]+)+\.?)\s*:\s*(\d{1,5})(?:$|[\s),])", text)
    if m:
        return m.group(2), _norm(m.group(1))
    # Tuple/repr form commonly starts with (target, port, priority, weight).
    m = re.search(r"['\"]([^'\"]+\.local\.?)['\"]\s*,\s*(\d{1,5})\b", text, re.I)
    if m:
        return m.group(2), _norm(m.group(1))
    # Some Scapy versions render ``port=631`` and ``target='host.local.'``
    # with arbitrary field ordering; parse independently as a final fallback.
    m = re.search(r"\bport\s*[=:]\s*(\d{1,5})", text, re.I)
    t = re.search(r"\btarget\s*[=:]\s*['\"]?([^,;\s'\"]+)", text, re.I)
    return (m.group(1) if m else "", _norm(t.group(1)) if t else "")


def build_service_chains(packets):
    """Correlate PTR -> SRV/TXT -> A/AAAA records across the capture.

    Repeated identical RRs are deduplicated. TTL-zero goodbye records remove an
    exact RR from the active view. At the end of a timestamped capture, records
    whose TTL has elapsed are excluded. Conflicting live SRV targets/ports are
    surfaced instead of silently hidden. Capture-wide correlation is evidence,
    not a claim that all records coexisted on the wire at one instant.
    """
    rr_state = {}  # (owner, type, normalized value) -> last observation metadata
    max_ts = None
    for packet in packets or []:
        try:
            ts = float(packet.get("timestamp")) if packet.get("timestamp") is not None else None
        except (TypeError, ValueError):
            ts = None
        if ts is not None:
            max_ts = ts if max_ts is None else max(max_ts, ts)
        src = str(packet.get("source") or "unknown")
        for rr in packet.get("records", []) or []:
            owner = _norm(rr.get("name")); typ = str(rr.get("type") or "").upper()
            value = str(rr.get("value") or "")
            if not owner or not typ:
                continue
            # DNS names are case-insensitive, but TXT RDATA is opaque application
            # metadata and may be case-sensitive. Preserve TXT bytes-as-decoded so
            # distinct TXT payloads are never collapsed by lowercasing.
            normalized_value = _norm(value) if typ in ("PTR", "SRV", "A", "AAAA") else value
            key = (owner, typ, normalized_value)
            try: ttl = max(0, int(rr.get("ttl", 120)))
            except (TypeError, ValueError): ttl = 0
            if ttl == 0:
                rr_state.pop(key, None)  # goodbye: remove this exact RR
                continue
            state = rr_state.setdefault(key, {"owner": owner, "type": typ, "value": value,
                                               "ttl": ttl, "timestamp": ts, "sources": set(), "count": 0})
            state.update(value=value, ttl=ttl, timestamp=ts if ts is not None else state.get("timestamp"))
            state["sources"].add(src); state["count"] += 1
    records = []
    for item in rr_state.values():
        ts = item.get("timestamp")
        if max_ts is not None and ts is not None and item["ttl"] > 0 and max_ts - ts > item["ttl"]:
            continue
        records.append(item)

    instances = {}
    srv_by_owner = defaultdict(list); txt_by_owner = defaultdict(list); addresses = defaultdict(set)
    for rr in records:
        owner, typ, value = rr["owner"], rr["type"], rr["value"]
        srcs = rr["sources"]
        if (typ == "PTR" and ("._tcp.local" in owner or "._udp.local" in owner)
                and not owner.startswith("_services._dns-sd._udp.local")
                and not owner.startswith("_dns-sd._udp.local")):
            inst = _norm(value)
            if inst:
                row = instances.setdefault(inst, {"instance": value.rstrip("."), "service_type": owner,
                    "target": "", "port": "", "txt": [], "addresses": set(), "sources": set(),
                    "evidence": set(), "status": "PTR only", "conflicts": [], "record_counts": {}, "ttl_remaining": {}})
                row["sources"].update(srcs); row["evidence"].add("PTR")
                row["record_counts"]["PTR"] = row["record_counts"].get("PTR", 0) + rr["count"]
                row["ttl_remaining"]["PTR"] = rr["ttl"]
        elif typ == "SRV":
            port, target = _srv(value)
            srv_by_owner[owner].append((port, target, srcs, rr["ttl"], rr["count"], value, rr.get("timestamp")))
        elif typ == "TXT":
            txt_by_owner[owner].append((value, srcs, rr["ttl"], rr["count"]))
        elif typ in ("A", "AAAA") and value:
            addresses[owner].add(value)

    for key, row in instances.items():
        srvs = srv_by_owner.get(key, [])
        if srvs:
            distinct = {(x[0], x[1]) for x in srvs}
            # Latest observed surviving SRV wins for the displayed target; conflicts remain visible.
            chosen = max(srvs, key=lambda x: (x[6] if x[6] is not None else float("-inf"), x[3], x[4]))
            port, target, srcs, ttl, count, raw, _observed_at = chosen
            row["port"], row["target"] = port, target
            row["sources"].update(srcs); row["evidence"].add("SRV")
            row["record_counts"]["SRV"] = sum(x[4] for x in srvs); row["ttl_remaining"]["SRV"] = ttl
            if len(distinct) > 1:
                row["conflicts"].append("Multiple live SRV targets or ports observed: " + "; ".join(sorted(f"{p or '?'} → {t or '?'}" for p, t in distinct)))
        for value, srcs, ttl, count in txt_by_owner.get(key, []):
            if value not in row["txt"]: row["txt"].append(value)
            row["sources"].update(srcs); row["evidence"].add("TXT")
            row["record_counts"]["TXT"] = row["record_counts"].get("TXT", 0) + count
            row["ttl_remaining"]["TXT"] = max(row["ttl_remaining"].get("TXT", 0), ttl)
        if row["target"]:
            row["addresses"] = set(addresses.get(row["target"], set()))
            if row["addresses"]:
                row["evidence"].add("A/AAAA")
                row["status"] = "Conflicting SRV records" if row["conflicts"] else "Complete chain"
            else: row["status"] = "Conflicting SRV records" if row["conflicts"] else "SRV target has no address observed"
        elif row["txt"]: row["status"] = "PTR/TXT observed; SRV missing"
        row["sources"].update(src for src in row["sources"])
        row["duplicate_observations"] = sum(max(0, n - 1) for n in row["record_counts"].values())
    return sorted(({**r, "addresses": sorted(r["addresses"]), "sources": sorted(r["sources"]),
                    "evidence": sorted(r["evidence"]), "txt": sorted(r["txt"]),
                    "conflicts": list(r["conflicts"])} for r in instances.values()),
                  key=lambda r: (r["service_type"].lower(), r["instance"].lower()))


def compare_discoveries(passive_chains, active_results):
    """Compare service instances by normalized DNS-SD full name."""
    passive = {_norm(x.get("instance")): x for x in passive_chains if _norm(x.get("instance"))}
    active = {}
    for x in active_results or []:
        key = _norm(x.get("fullname") or x.get("instance"))
        if key: active[key] = x
    rows = []
    for key in sorted(set(passive) | set(active)):
        p, a = passive.get(key), active.get(key)
        if p and a:
            interp = "Seen by both methods"
            if p.get("target") and a.get("host") and _norm(p["target"]) != _norm(a["host"]): interp = "Both seen · target differs"
            elif p.get("port") and a.get("port") and str(p["port"]) != str(a["port"]): interp = "Both seen · port differs"
            if p.get("conflicts"): interp += " · passive SRV conflict"
        elif p: interp = "Passive only · may not be browsed/resolved"
        else: interp = "Active only · not observed in captured traffic"
        rows.append({"service_instance": key, "passive_seen": bool(p), "active_seen": bool(a),
                     "target": (a or {}).get("host") or (p or {}).get("target", ""),
                     "port": (a or {}).get("port") or (p or {}).get("port", ""),
                     "interpretation": interp, "passive_status": (p or {}).get("status", ""),
                     "active_status": (a or {}).get("status", ""), "passive_conflicts": (p or {}).get("conflicts", [])})
    return rows
