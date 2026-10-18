"""Validation helpers for saved mDNS Observatory sessions."""
from __future__ import annotations

PACKET_FIELDS = ("source", "destination", "mac", "vlan", "time", "direction",
                 "questions", "records", "rr_types")


def validate_session_payload(data):
    """Validate a session fully before callers replace their current dataset.

    Older session JSON without a session_format marker remains supported. Invalid
    packet entries are rejected rather than silently skipped, avoiding partial
    restores that look successful but produce incomplete reports.
    """
    if not isinstance(data, dict):
        raise ValueError("Session root must be a JSON object.")
    fmt = data.get("session_format")
    if fmt not in (None, "mdns-observatory-session-v1"):
        raise ValueError(f"Unsupported session format: {fmt}")
    packets = data.get("packets")
    if not isinstance(packets, list):
        raise ValueError("This JSON file does not contain a packet session.")
    if len(packets) > 100000:
        raise ValueError("Session contains more than 100,000 packets, exceeding the supported session limit.")
    for index, packet in enumerate(packets):
        if not isinstance(packet, dict):
            raise ValueError(f"Packet {index + 1} is not an object.")
        missing = [key for key in PACKET_FIELDS if key not in packet]
        if missing:
            raise ValueError(f"Packet {index + 1} is missing required fields: {', '.join(missing)}.")
        for field in ("source", "destination", "mac", "vlan", "time", "direction"):
            if not isinstance(packet[field], str):
                raise ValueError(f"Packet {index + 1} field '{field}' must be text.")
        if not isinstance(packet["questions"], list) or not isinstance(packet["records"], list) or not isinstance(packet["rr_types"], list):
            raise ValueError(f"Packet {index + 1} has invalid questions, records, or record-type data.")
        if any(not isinstance(value, str) for value in packet["rr_types"]):
            raise ValueError(f"Packet {index + 1} has invalid record-type entries.")
        if packet["direction"] not in ("Query", "Response"):
            raise ValueError(f"Packet {index + 1} has an invalid direction.")
        for label, entries in (("question", packet["questions"]), ("record", packet["records"])):
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError(f"Packet {index + 1} contains a non-object {label}.")
                if not isinstance(entry.get("name"), str) or not entry.get("name") or not isinstance(entry.get("type"), str) or not entry.get("type"):
                    raise ValueError(f"Packet {index + 1} contains a {label} without a text name or type.")
                if label == "record" and "ttl" in entry:
                    try:
                        ttl = int(entry["ttl"])
                    except (TypeError, ValueError):
                        raise ValueError(f"Packet {index + 1} contains a record with an invalid TTL.")
                    if ttl < 0:
                        raise ValueError(f"Packet {index + 1} contains a negative record TTL.")
    if "packet_history_truncated" in data and not isinstance(data["packet_history_truncated"], bool):
        raise ValueError("Session field 'packet_history_truncated' must be true or false.")
    if "diagnostics" in data and not isinstance(data["diagnostics"], dict):
        raise ValueError("Session field 'diagnostics' must be an object.")
    for field in ("active_discoveries", "discovery_events", "intended_rules"):
        value = data.get(field, [])
        if not isinstance(value, list):
            raise ValueError(f"Session field '{field}' must be a list.")
        if any(not isinstance(item, dict) for item in value):
            raise ValueError(f"Session field '{field}' contains an invalid entry.")
    return {
        "packets": packets,
        "active_discoveries": data.get("active_discoveries", []),
        "discovery_events": data.get("discovery_events", [])[-5000:],
        "intended_rules": data.get("intended_rules", []),
        "packet_history_truncated": bool(data.get("packet_history_truncated", False)),
        "stored_packet_count": len(packets),
    }


def restore_diagnostics(saved_diagnostics, stored_packet_count):
    """Restore non-derived diagnostics without overstating rebuilt packet totals.

    Device/service/group counters are rebuilt from the retained packet list. A
    historical mdns_packets_accepted value may include packets no longer stored,
    so that value must be reset to the number actually replayed. Capture-wide
    frame counts and the truncation marker remain useful historical diagnostics.
    """
    restored = {}
    if isinstance(saved_diagnostics, dict):
        for key, value in saved_diagnostics.items():
            if isinstance(value, (int, float)) and value >= 0:
                restored[key] = value
    restored["mdns_packets_accepted"] = int(stored_packet_count)
    return restored
