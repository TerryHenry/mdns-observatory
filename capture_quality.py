"""Evidence-based capture quality checks; deliberately avoids diagnosing faults from absence alone."""
from __future__ import annotations


def assess_capture_quality(*, diagnostics=None, packet_count=0, capture_started=None,
                           capture_error="", packet_history_truncated=False):
    d = dict(diagnostics or {})
    frames = int(d.get("frames_seen", 0) or 0)
    accepted = int(d.get("mdns_packets_accepted", 0) or 0)
    decode_errors = int(d.get("live_decode_errors", 0) or 0) + int(d.get("decode_errors", 0) or 0)
    misses = int(d.get("live_port_5353_not_decoded", 0) or 0) + int(d.get("port_5353_not_decoded_as_dns", 0) or 0)
    findings = []

    if capture_error:
        findings.append({"severity": "high", "code": "capture_error", "title": "Capture reported an error",
                         "detail": str(capture_error).splitlines()[0],
                         "action": "Review the capture error and runtime diagnostics; retry after checking interface selection and capture permissions."})
    if capture_started and frames == 0 and not capture_error:
        findings.append({"severity": "medium", "code": "no_frames", "title": "No frames reached the decoder",
                         "detail": "The capture session has no observed frames. A running indicator alone does not establish that the interface is receiving packets.",
                         "action": "Confirm the selected interface is active, check macOS packet-capture permissions, and generate known local network traffic. Then retry."})
    elif frames > 0 and accepted == 0:
        findings.append({"severity": "info", "code": "no_mdns_observed", "title": "Frames seen, but no mDNS packets accepted",
                         "detail": f"{frames:,} frames reached the decoder; none were retained as mDNS. This may simply mean the capture window contained no mDNS traffic.",
                         "action": "Capture during service discovery or a known Bonjour exchange; verify interface and capture point before treating this as a problem."})
    elif accepted > 0:
        findings.append({"severity": "ok", "code": "mdns_observed", "title": "mDNS evidence observed",
                         "detail": f"{accepted:,} mDNS packet(s) accepted from {frames:,} frame(s) seen by the decoder.",
                         "action": "Use packet and service evidence for the next diagnostic step."})
    if misses:
        findings.append({"severity": "medium", "code": "decode_misses", "title": "Some UDP/5353 frames were not decoded as DNS",
                         "detail": f"{misses:,} UDP/5353 decode miss(es) recorded.",
                         "action": "Inspect decoder diagnostics and the capture link type. These misses may include malformed or non-DNS payloads; they do not automatically indicate a capture failure."})
    if decode_errors:
        findings.append({"severity": "medium", "code": "decode_errors", "title": "Decoder errors recorded",
                         "detail": f"{decode_errors:,} decoder error(s) recorded.",
                         "action": "Inspect the error details and sample packets. Isolated malformed frames may not invalidate the rest of the capture."})
    if packet_history_truncated or d.get("packet_history_truncated"):
        findings.append({"severity": "info", "code": "history_truncated", "title": "Packet history is truncated",
                         "detail": "Only retained packet history is available for packet-level views and derived analysis.",
                         "action": "Use the original PCAP/PCAPNG as the authoritative full evidence set when possible."})
    if not findings:
        findings.append({"severity": "info", "code": "awaiting_evidence", "title": "Not enough capture evidence yet",
                         "detail": "No capture quality condition could be assessed from the available counters.",
                         "action": "Start a capture or import a file to collect evidence."})
    return {"frames_seen": frames, "mdns_packets_accepted": accepted, "packet_count": int(packet_count or 0),
            "capture_started": bool(capture_started), "findings": findings,
            "caveat": "These checks describe observed capture evidence. They cannot prove that a service is unavailable or that a network path is faulty."}


def format_capture_quality(result):
    lines = ["CAPTURE QUALITY TRIAGE", f"Frames seen by decoder: {result['frames_seen']:,}",
             f"mDNS packets accepted: {result['mdns_packets_accepted']:,}", ""]
    for item in result["findings"]:
        lines += [f"[{item['severity'].upper()}] {item['title']}", f"  Evidence: {item['detail']}", f"  Next step: {item['action']}", ""]
    lines.append("Caveat: " + result["caveat"])
    return "\n".join(lines)
