"""Build privacy-conscious support bundles without packet payloads by default."""
from __future__ import annotations
import json
import platform
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def build_support_bundle(path, *, diagnostics, analyzer_snapshot, discovery_events=(), app_version="unknown"):
    """Write a small ZIP bundle with runtime details and aggregate app state.

    Raw packet evidence is intentionally excluded. Interface names and discovery
    event details may still be sensitive, so the UI should disclose that clearly.
    """
    snapshot = analyzer_snapshot or {}
    aggregate = {
        "app_version": str(app_version),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "stored_packet_count": int(snapshot.get("stored_packet_count", snapshot.get("packet_count", len(snapshot.get("packets", []) or []))) or 0),
        "device_count": len(snapshot.get("devices", []) or []),
        "service_count": len(snapshot.get("services", []) or []),
        "groups": snapshot.get("groups", {}),
        "record_types": snapshot.get("record_types", {}),
        "capture_error": snapshot.get("capture_error", ""),
        "diagnostics": snapshot.get("diagnostics", {}),
        "packet_history_truncated": bool(snapshot.get("packet_history_truncated", False)),
        "discovery_event_count": len(list(discovery_events or [])),
    }
    events = [dict(event) for event in list(discovery_events or [])[-500:]]
    readme = (
        "mDNS Observatory support bundle\n"
        "===============================\n\n"
        "Contents: runtime diagnostics, aggregate capture state, and up to 500 recent Bonjour events.\n"
        "Raw packet rows and packet payloads are not included.\n"
        "Privacy note: interface names, host/service names, addresses, and error text may appear in diagnostics/events.\n"
        "Review the files before sharing them.\n"
    )
    path = Path(path)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", readme)
        archive.writestr("runtime-diagnostics.json", json.dumps(diagnostics, indent=2, ensure_ascii=False, default=str))
        archive.writestr("capture-summary.json", json.dumps(aggregate, indent=2, ensure_ascii=False, default=str))
        archive.writestr("bonjour-events.json", json.dumps(events, indent=2, ensure_ascii=False, default=str))
    return path
