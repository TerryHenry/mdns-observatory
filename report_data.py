"""Canonical, deterministic report-data assembly shared by exports and tests."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy

from discovery_diagnostics import summarize_discovery_events
from service_correlation import build_service_chains, compare_discoveries
from traffic_intelligence import build_traffic_intelligence


def build_export_snapshot(analyzer_snapshot, active_discoveries=(), discovery_events=()):
    """Create one consistent export model from a passive snapshot and active evidence.

    The input snapshot is never mutated. All derived views are computed from the same
    retained packet list so JSON, HTML, and CSV exports cannot accidentally use
    different packet subsets or different active-discovery snapshots.
    """
    result = deepcopy(analyzer_snapshot)
    packets = result.get("packets", [])
    active = [deepcopy(x) for x in active_discoveries if isinstance(x, dict)]
    events = [deepcopy(x) for x in discovery_events if isinstance(x, dict)]
    stored_count = len(packets)
    truncated = bool(result.get("packet_history_truncated"))
    result["active_discoveries"] = active
    result["discovery_events"] = events
    result["export_scope"] = {
        "stored_packet_count": stored_count,
        "packet_history_truncated": truncated,
        "packet_history_limit": 100000,
        "analysis_scope": "retained packet history only",
    }
    result["discovery_diagnostics"] = summarize_discovery_events(events)
    chains = build_service_chains(packets)
    result["service_chains"] = chains
    result["comparison"] = compare_discoveries(chains, active)
    traffic = build_traffic_intelligence(packets)
    result["traffic_intelligence"] = {
        "families": dict(traffic["families"]),
        "directions": dict(traffic["directions"]),
        "top_sources": traffic["sources"].most_common(12),
        "vlan_evidence": traffic["vlans"].most_common(12),
        "repeated_query_candidates": [
            {"name": name, "type": record_type, "count": count}
            for name, record_type, count in traffic["candidate_queries"]
        ],
        "minute_bins": dict(sorted(traffic["minute_bins"].items())),
    }
    return result
