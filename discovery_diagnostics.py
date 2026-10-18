"""Small, deterministic helpers for surfacing native Bonjour discovery failures."""
from collections import Counter


def summarize_discovery_events(events):
    """Return a privacy-conscious summary of discovery errors and event counts.

    Event history is user-provided/local diagnostic data. Keep only bounded, useful
    fields in the summary; full events remain available in the session export.
    """
    counts = Counter()
    errors = []
    for event in events or []:
        if not isinstance(event, dict):
            continue
        kind = str(event.get("event") or "unknown")[:40]
        counts[kind] += 1
        if kind in ("error", "resolve_error"):
            message = str(event.get("error") or event.get("status") or "Unknown discovery error").strip()
            errors.append({
                "event": kind,
                "time": str(event.get("time") or "")[:80],
                "service_type": str(event.get("service_type") or "")[:255],
                "instance": str(event.get("instance") or event.get("fullname") or "")[:255],
                "error": message[:1000],
            })
    return {
        "event_counts": dict(sorted(counts.items())),
        "error_count": len(errors),
        "recent_errors": errors[-20:],
    }
