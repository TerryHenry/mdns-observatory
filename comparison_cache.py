"""Stable cache keys for passive/active DNS-SD comparison results."""
from __future__ import annotations


def discovery_signature(discoveries):
    """Return a deterministic signature for fields that affect comparison output."""
    rows = []
    for item in discoveries or []:
        if not isinstance(item, dict):
            continue
        rows.append((
            str(item.get("fullname") or item.get("instance") or "").rstrip(".").casefold(),
            str(item.get("service_type") or "").rstrip(".").casefold(),
            str(item.get("host") or "").rstrip(".").casefold(),
            str(item.get("port") or ""),
            str(item.get("txt") or ""),
            str(item.get("status") or ""),
        ))
    return tuple(sorted(rows))


def comparison_cache_key(analyzer_identity, packet_revision, discoveries):
    """Key cache by analyzer instance, packet generation and active results."""
    return (analyzer_identity, int(packet_revision), discovery_signature(discoveries))
