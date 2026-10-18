"""Evidence-weighted troubleshooting hypotheses for mDNS/Bonjour captures.

Scores are transparent heuristic priorities, not calibrated probabilities.
Evidence references are zero-based indices into the supplied packet list.
"""
from collections import Counter


def rank_likely_causes(packets, symptom="general", service_query="", client_query=""):
    packets = list(packets or [])
    service = str(service_query or "").strip().lower().rstrip(".")
    client = str(client_query or "").strip().lower()
    matched = []
    for i, p in enumerate(packets):
        records = p.get("records", []) or []
        text = " ".join([str(p.get(k, "")) for k in ("summary", "question", "questions", "source", "destination")] + [
            " ".join(f"{r.get('name','')} {r.get('type','')} {r.get('value','')}" for r in records)]) .lower()
        if service and service not in text:
            continue
        if client and client not in (str(p.get("source", "")).lower() + " " + str(p.get("destination", "")).lower()):
            continue
        matched.append((i, p))

    query = [(i,p) for i,p in matched if str(p.get("direction", "")).lower() == "query"]
    response = [(i,p) for i,p in matched if str(p.get("direction", "")).lower() == "response"]
    records = [(i,p,r) for i,p in matched for r in (p.get("records", []) or [])]
    types = Counter(str(r.get("type", "")).upper() for _,_,r in records)
    vlans = {str(p.get("vlan")) for _,p in matched if p.get("vlan") not in (None, "", "-", "unknown")}
    multicast = [(i,p) for i,p in matched if "224.0.0.251" in str(p.get("destination", "")) or "ff02::fb" in str(p.get("destination", "")).lower()]
    sources = Counter(str(p.get("source", "unknown")) for _,p in matched if p.get("direction", "").lower() == "response")

    causes = []
    def add(title, score, supports, weakens, next_test, refs=()):
        causes.append({"cause": title, "score": max(0, min(100, int(score))),
                       "supports": supports, "weakens": weakens, "next_test": next_test,
                       "evidence_indices": sorted(set(int(x) for x in refs))[:30],
                       "score_note": "Heuristic priority, not a probability."})

    no_evidence = len(matched) == 0
    if no_evidence:
        add("Capture point or filter does not include the relevant exchange", 72,
            f"No retained packets matched the current filters ({len(packets)} total packet(s) retained).",
            "This does not distinguish a quiet network from a wrong interface, short capture window, or overly specific filter.",
            "Clear the filters, confirm the affected interface/VLAN, then reproduce a discovery attempt while capturing.")
    else:
        add("Capture visibility or observation window is incomplete", 42 if len(matched) < 3 else 25,
            f"Only {len(matched)} packet(s) match the selected scope; evidence covers only this capture point and time window.",
            f"{len(matched)} matching packet(s) are available for inspection." if len(matched) >= 3 else "A small sample cannot establish whether traffic is consistently absent.",
            "Capture a longer, controlled reproduction and, if possible, observe both client and service-side segments.", [i for i,_ in matched])

    if query and not response:
        score = 78 if symptom in ("client_cannot_discover", "intermittent", "cross_vlan") else 58
        add("Queries are visible but no matching response is retained", score,
            f"Observed {len(query)} matching query packet(s) and zero matching response packet(s).",
            "Responses may be unicast, outside the selected filter/window, or invisible at this capture point; multicast queries do not prove which hosts received them.",
            "Inspect the exact queried name/type, then capture simultaneously near the client and service. Check responder state and multicast/Bonjour gateway policy.", [i for i,_ in query])
    elif query and response:
        add("The exchange is at least partly visible; investigate beyond basic discovery", 22,
            f"Observed {len(query)} query packet(s) and {len(response)} response packet(s) in scope.",
            "This proves only that query/response-shaped packets were captured, not that the affected client received or accepted them.",
            "Check response contents and timing, then test the advertised target IP/port and client application behavior.", [i for i,_ in query + response])

    if symptom == "service_not_resolving" or ("SRV" in types and not ("A" in types or "AAAA" in types)):
        missing = [t for t in ("SRV", "TXT", "A/AAAA") if (t == "SRV" and not types["SRV"]) or (t == "TXT" and not types["TXT"]) or (t == "A/AAAA" and not (types["A"] or types["AAAA"]))]
        add("DNS-SD resolution chain may be incomplete", 70 if missing else 30,
            f"Observed record types: {', '.join(f'{k} ({v})' for k,v in sorted(types.items())) or 'none'}. Missing from this filtered evidence: {', '.join(missing) or 'no obvious SRV/TXT/address category'}.",
            "Records may have been cached, sent in separate packets, or omitted by the capture filter/window.",
            "Follow PTR instance → SRV target/port → TXT metadata → target A/AAAA; then test application reachability separately.", [i for i,_,_ in records])

    if symptom == "cross_vlan":
        add("Multicast is not being forwarded or reflected across the expected boundary", 66 if len(vlans) < 2 else 35,
            f"Visible VLAN labels in matching packets: {', '.join(sorted(vlans)) if vlans else 'none (capture may be untagged or VLAN metadata unavailable)'}.",
            "A single capture point cannot establish that a VLAN boundary is the cause; untagged frames do not identify a VLAN.",
            "Capture at both VLANs during the same attempt and verify Bonjour gateway/reflector, multicast policy, ACLs, and service-specific configuration.", [i for i,_ in matched])

    if symptom == "intermittent":
        add("Timing, cache state, or changing advertisements may be involved", 52,
            f"Observed {len(query)} query packet(s), {len(response)} response packet(s), and {len({str(p.get('source','')) for _,p in matched})} distinct source(s).",
            "One capture window cannot distinguish packet loss, sleep/wake behavior, cache effects, or application timing.",
            "Compare repeated successful and failed attempts; inspect timestamps, TTL-zero goodbye records, changing SRV targets/ports, and both-side packet visibility.", [i for i,_ in matched])

    if symptom == "unexpected_service":
        add("An unexpected advertisement is visible; ownership and intent remain unverified", 62 if records else 35,
            f"Captured {len(records)} DNS resource-record observation(s) from {len(sources)} response source(s).",
            "A hostname, service instance, or source address alone does not authenticate the device or prove malicious behavior.",
            "Inspect instance/type, SRV target/port, source MAC/IP, switch port and DHCP inventory; validate with the device owner before classifying it.", [i for i,_,_ in records])

    if not response and not query and matched:
        add("Selected packets do not show a clear query/response exchange", 48,
            f"{len(matched)} packet(s) matched, but {len(query)} were classified as queries and {len(response)} as responses.",
            "Direction labels or packet summaries may vary; some captured records may be unsolicited announcements.",
            "Open the referenced packets and inspect DNS flags, questions, answer records, and capture decoder details.", [i for i,_ in matched])

    # Prefer higher scores, with deterministic ordering for stable UI/tests.
    causes.sort(key=lambda x: (-x["score"], x["cause"]))
    for rank, cause in enumerate(causes, 1):
        cause["rank"] = rank
    return {"symptom": symptom, "matched_count": len(matched), "packet_total": len(packets),
            "causes": causes[:6], "evidence_scope": [i for i,_ in matched],
            "caveat": "Scores are rule-based investigation priorities, not statistical probabilities or confirmed root causes."}
