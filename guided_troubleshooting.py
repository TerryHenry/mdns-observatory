"""Evidence-led guided troubleshooting for common Bonjour discovery symptoms."""
from collections import Counter

SYMPTOMS = [
    ("client_cannot_discover", "A client cannot discover a Bonjour service"),
    ("service_not_resolving", "Service appears, but it will not resolve"),
    ("intermittent", "Discovery is intermittent or slow"),
    ("cross_vlan", "Discovery fails across VLANs / subnets"),
    ("unexpected_service", "An unexpected service or device appears"),
    ("general", "I want to understand this capture"),
]


def _norm(value):
    return str(value or "").strip().lower().rstrip(".")


def analyze_guided_issue(packets, symptom="general", service_query="", client_query=""):
    """Return a conservative, evidence-linked troubleshooting plan.

    Evidence references are zero-based indices into the supplied packet list.
    Absence is described as not observed, never proof of failure.
    """
    packets = list(packets or [])
    service_query = _norm(service_query)
    client_query = _norm(client_query)
    matched = []
    for index, packet in enumerate(packets):
        text = " ".join([
            str(packet.get("source", "")), str(packet.get("destination", "")),
            str(packet.get("direction", "")), str(packet.get("summary", "")),
            str(packet.get("question", "")), str(packet.get("questions", "")),
            " ".join(str(r.get("name", "")) + " " + str(r.get("value", "")) + " " + str(r.get("type", ""))
                     for r in (packet.get("records", []) or [])),
            " ".join(str(q) for q in (packet.get("questions", []) or []) if isinstance(q, (str, int, float))),
        ]).lower()
        if service_query and service_query not in text:
            continue
        if client_query and client_query not in str(packet.get("source", "")).lower() and client_query not in str(packet.get("destination", "")).lower():
            continue
        matched.append({"index": index, "packet": packet})

    queries = [x for x in matched if str(x["packet"].get("direction", "")).lower() == "query"]
    responses = [x for x in matched if str(x["packet"].get("direction", "")).lower() == "response"]
    source_counts = Counter(str(x["packet"].get("source", "unknown")) for x in matched)
    vlan_counts = Counter(str(x["packet"].get("vlan") or "Untagged / not visible") for x in matched)
    record_types = Counter(str(r.get("type", "?")).upper() for x in matched for r in (x["packet"].get("records", []) or []))

    steps = []
    def add(title, status, evidence, action, confidence="Guidance"):
        steps.append({"title": title, "status": status, "evidence": evidence,
                      "action": action, "confidence": confidence})

    add("1. Confirm capture visibility", "Evidence scoped", f"{len(packets)} retained packet(s) available; {len(matched)} match the selected filters.",
        "Capture on the affected client's actual network interface or a known-good mirror point. Confirm the observation window includes a discovery attempt.", "Baseline")
    if not matched:
        add("2. Narrow the evidence", "No matching packets", "No retained packets matched the selected service/client text. This is not proof that the service or client is absent.",
            "Clear one or both filters, check spelling/case-insensitive service names, and verify that the imported capture includes UDP/5353 traffic.", "Observed limitation")
    else:
        add("2. Check the discovery exchange", f"{len(queries)} query packet(s), {len(responses)} response packet(s) matched.",
            f"Matching packet indices: {', '.join(str(x['index']) for x in matched[:12])}{'…' if len(matched) > 12 else ''}.",
            "Open packet evidence and verify the queried DNS-SD name/type, response contents, and timestamps. Counts are not a success rate; multicast visibility does not prove delivery.", "Observed")
        if symptom in ("client_cannot_discover", "cross_vlan", "general"):
            add("3. Verify the advertisement", "Record evidence", "Observed record types: " + (", ".join(f"{k} ({v})" for k,v in sorted(record_types.items())) if record_types else "no DNS resource records in matching packets"),
                "For service discovery, look for a PTR advertisement for the service type, then follow the instance to SRV/TXT and the target's A/AAAA records. Missing records may be outside the capture window.", "Interpretation")
        if symptom == "service_not_resolving":
            add("3. Follow the resolution chain", "Record evidence", "Observed record types: " + (", ".join(f"{k} ({v})" for k,v in sorted(record_types.items())) if record_types else "no DNS resource records in matching packets"),
                "Check SRV target and port, TXT metadata, and A/AAAA records for the target. Then test reachability to the advertised target/port separately; mDNS alone does not prove application reachability.", "Interpretation")
        if symptom in ("intermittent", "unexpected_service"):
            add("3. Compare timing and sources", "Observed", f"Top sources: {', '.join(f'{k} ({v})' for k,v in source_counts.most_common(5)) or 'none'}.",
                "Compare multiple equivalent time windows. Look for repeated queries, changing targets/ports, TTL-zero goodbye records, and conflicting advertisements before attributing a cause.", "Interpretation")
        if symptom == "cross_vlan":
            add("4. Validate the network path", "Visibility check", f"Observed VLAN labels: {', '.join(f'{k} ({v})' for k,v in vlan_counts.items())}.",
                "Capture simultaneously on both sides of the expected path. Verify multicast forwarding or Bonjour gateway/service-reflector design, ACLs, and VLAN policy. Untagged capture does not identify a VLAN by itself.", "Hypothesis to test")
        else:
            add("4. Validate actual service use", "Not measured by mDNS alone", "Packet evidence can show advertisements and responses, but not whether the client received them or the application connection succeeded.",
                "Reproduce the issue while capturing; then test the advertised IP/port and inspect application/client logs. Correlate timestamps across both sides when possible.", "Hypothesis to test")
    return {"symptom": symptom, "service_query": service_query, "client_query": client_query,
            "packet_total": len(packets), "matched_count": len(matched), "evidence_indices": [x["index"] for x in matched],
            "evidence": [{"index": x["index"], "time": x["packet"].get("time", ""),
                          "direction": x["packet"].get("direction", ""), "source": x["packet"].get("source", ""),
                          "destination": x["packet"].get("destination", ""),
                          "summary": x["packet"].get("summary", "") or ", ".join(str(r.get("name", "")) + " " + str(r.get("type", "")) for r in (x["packet"].get("records", []) or []))}
                         for x in matched[:500]], "steps": steps,
            "caveat": "This workflow organizes observed evidence and next checks. It does not prove service failure, multicast delivery, or a root cause."}
