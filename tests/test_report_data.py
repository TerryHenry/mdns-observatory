import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from report_data import build_export_snapshot


class ReportDataTests(unittest.TestCase):
    def sample_packet(self):
        return {
            "time": "2026-10-16T10:00:00-04:00", "source": "192.0.2.10",
            "destination": "224.0.0.251", "mac": "00:11:22:33:44:55",
            "vlan": "10", "family": "IPv4", "direction": "Query",
            "sport": 5353, "dport": 5353, "questions": [{"name": "_airplay._tcp.local", "type": "PTR"}],
            "records": [], "bytes": 90, "source_type": "query"
        }

    def test_export_views_share_one_packet_scope(self):
        source = {"generated_at": "now", "capture_started": "then", "packet_count": 1,
                  "stored_packet_count": 1, "packet_history_truncated": False,
                  "packets": [self.sample_packet()], "devices": [], "services": [],
                  "groups": {}, "record_types": {}, "capture_error": "", "diagnostics": {}}
        active = [{"fullname": "Living Room._airplay._tcp.local", "service_type": "_airplay._tcp",
                   "host": "speaker.local", "port": 7000, "txt": "model=Test"}]
        events = [{"event": "add", "instance": "Living Room", "service_type": "_airplay._tcp"},
                  {"event": "error", "error": "browse failed"}]
        exported = build_export_snapshot(source, active, events)
        self.assertEqual(exported["export_scope"]["stored_packet_count"], len(exported["packets"]))
        self.assertEqual(exported["discovery_diagnostics"]["event_counts"], {"add": 1, "error": 1})
        self.assertEqual(exported["discovery_diagnostics"]["error_count"], 1)
        self.assertEqual(exported["traffic_intelligence"]["families"], {"IPv4": 1})
        self.assertEqual(exported["traffic_intelligence"]["directions"], {"Query": 1})
        self.assertEqual(len(exported["comparison"]), 1)  # active-only services are retained in comparison
        self.assertFalse(exported["comparison"][0]["passive_seen"])
        self.assertTrue(exported["comparison"][0]["active_seen"])
        self.assertEqual(exported["active_discoveries"], active)
        # Caller data must not be mutated or aliased by the export model.
        exported["active_discoveries"][0]["port"] = 123
        self.assertEqual(active[0]["port"], 7000)
        self.assertNotIn("service_chains", source)

    def test_truncated_history_is_explicit_and_derived_data_is_retained_scope(self):
        source = {"packet_count": 500, "stored_packet_count": 1, "packet_history_truncated": True,
                  "packets": [self.sample_packet()], "devices": [], "services": [], "diagnostics": {}}
        exported = build_export_snapshot(source)
        self.assertTrue(exported["export_scope"]["packet_history_truncated"])
        self.assertEqual(exported["export_scope"]["analysis_scope"], "retained packet history only")
        self.assertEqual(exported["export_scope"]["stored_packet_count"], 1)
        self.assertEqual(exported["traffic_intelligence"]["minute_bins"], {"2026-10-16 10:00": 1})

    def test_malformed_event_entries_are_ignored_without_mutating_source(self):
        source = {"packets": [], "diagnostics": {}}
        events = [None, "bad", {"event": "resolve_error", "error": "timeout"}]
        exported = build_export_snapshot(source, [], events)
        self.assertEqual(exported["discovery_diagnostics"]["error_count"], 1)
        self.assertEqual(len(exported["discovery_events"]), 1)
        self.assertEqual(events[0], None)


if __name__ == "__main__":
    unittest.main()
