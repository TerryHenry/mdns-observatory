"""Pure, dependency-free traffic analytics for mDNS Observatory."""
from collections import Counter
from datetime import datetime

def build_traffic_intelligence(packets):
    """Return conservative, reproducible traffic summaries from decoded mDNS packets."""
    from collections import Counter
    from datetime import datetime
    families = Counter(str(p.get("family", "unknown")) for p in packets)
    directions = Counter(str(p.get("direction", "unknown")) for p in packets)
    sources = Counter(str(p.get("source") or "unknown") for p in packets)
    vlans = Counter(str(p.get("vlan") or "Unknown / not tagged") for p in packets)
    query_names = Counter()
    response_names = Counter()
    for packet in packets:
        if packet.get("direction") == "Query":
            for q in packet.get("questions", []):
                query_names[(str(q.get("name", "")).rstrip(".").lower(), str(q.get("type", "ANY")))] += 1
        elif packet.get("direction") == "Response":
            for rr in packet.get("records", []):
                response_names[(str(rr.get("name", "")).rstrip(".").lower(), str(rr.get("type", "")))] += 1
    # This is a name/type correlation hint, not a DNS transaction tracker: mDNS
    # responses may answer PTR questions with records under related owner names.
    candidates = [(name, typ, count) for (name, typ), count in query_names.items()
                  if count >= 2 and not response_names.get((name, typ), 0)]
    bins = Counter()
    for packet in packets:
        try:
            dt = datetime.fromisoformat(str(packet.get("time", "")))
            bins[dt.replace(second=0, microsecond=0).strftime("%Y-%m-%d %H:%M")] += 1
        except Exception:
            continue
    return {"families": families, "directions": directions, "sources": sources,
            "vlans": vlans, "query_names": query_names, "candidate_queries": candidates,
            "minute_bins": bins}

