"""Small, deterministic source-to-destination summaries for observed mDNS packets."""
from collections import Counter
import ipaddress


def build_flow_summary(packets):
    flows = {}
    sources, destinations = Counter(), Counter()
    for pkt in packets or []:
        source = str(pkt.get("source") or "Unknown")
        destination = str(pkt.get("destination") or "Unknown")
        key = (source, destination)
        timestamp = str(pkt.get("time") or "")
        flow = flows.setdefault(key, {"packets": 0, "queries": 0, "responses": 0,
                                      "first": timestamp, "last": timestamp})
        flow["packets"] += 1
        flow["queries"] += int(pkt.get("direction") == "Query")
        flow["responses"] += int(pkt.get("direction") == "Response")
        if timestamp:
            flow["first"] = min(filter(None, (flow["first"], timestamp)), default=timestamp)
            flow["last"] = max(filter(None, (flow["last"], timestamp)), default=timestamp)
        sources[source] += 1
        destinations[destination] += 1
    rows = []
    for (source, destination), flow in sorted(flows.items(), key=lambda item: (-item[1]["packets"], item[0])):
        try:
            multicast = ipaddress.ip_address(destination).is_multicast
        except ValueError:
            multicast = False
        rows.append([source, destination, "Multicast group" if multicast else "Observed unicast",
                     flow["packets"], flow["queries"], flow["responses"], flow["first"], flow["last"]])
    return {"rows": rows, "sources": sources, "destinations": destinations}


def packet_service_types(packet):
    """Return DNS-SD service types visible in a decoded packet's questions/records."""
    import re
    found = set()
    pattern = re.compile(r"_[a-z0-9-]+\._(?:tcp|udp)\.local\.?", re.IGNORECASE)

    def visit(value):
        if isinstance(value, dict):
            for child in value.values():
                visit(child)
        elif isinstance(value, (list, tuple, set)):
            for child in value:
                visit(child)
        elif isinstance(value, str):
            found.update(match.lower().rstrip(".") for match in pattern.findall(value))

    for key in ("services", "questions", "records"):
        visit(packet.get(key, []))
    return found


def filter_flow_packets(packets, ip_filter="", multicast_group="All groups",
                        service_type="All service types", minutes=None):
    """Filter decoded packets for the Flow view. Time is relative to newest capture packet."""
    import ipaddress
    from datetime import datetime

    packets = list(packets or [])

    def timestamp(packet):
        value = packet.get("timestamp")
        if isinstance(value, (int, float)):
            return float(value)
        try:
            return datetime.fromisoformat(str(packet.get("time", "")).replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError, OverflowError):
            return None

    stamps = [v for v in (timestamp(packet) for packet in packets) if v is not None]
    cutoff = max(stamps) - int(minutes) * 60 if minutes and stamps else None
    needle = str(ip_filter or "").strip().casefold()
    result = []
    for packet in packets:
        src = str(packet.get("source") or "Unknown")
        dst = str(packet.get("destination") or "Unknown")
        if needle and needle not in src.casefold() and needle not in dst.casefold():
            continue
        if multicast_group != "All groups" and dst != multicast_group:
            continue
        if service_type != "All service types" and service_type not in packet_service_types(packet):
            continue
        ts = timestamp(packet)
        if cutoff is not None and (ts is None or ts < cutoff):
            continue
        result.append(packet)
    return result
