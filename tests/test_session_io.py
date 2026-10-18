import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from session_io import validate_session_payload, restore_diagnostics


def packet():
    return {
        "source": "192.0.2.10", "destination": "224.0.0.251", "mac": "00:11:22:33:44:55",
        "vlan": "Unknown / not tagged", "time": "2026-10-16T10:00:00-04:00", "timestamp": 1792166400.0,
        "direction": "Query", "questions": [{"name": "_airplay._tcp.local", "type": "PTR"}],
        "records": [], "rr_types": ["PTR"], "family": "IPv4", "sport": 5353, "dport": 5353,
        "id": 0, "services": [], "source_type": "pcap", "bytes": 90,
    }


class SessionValidationTests(unittest.TestCase):
    def test_valid_legacy_session(self):
        result = validate_session_payload({"packets": [packet()]})
        self.assertEqual(len(result["packets"]), 1)
        self.assertEqual(result["active_discoveries"], [])

    def test_valid_versioned_session_and_caps_events(self):
        result = validate_session_payload({
            "session_format": "mdns-observatory-session-v1", "packets": [packet()],
            "discovery_events": [{"n": n} for n in range(5002)],
        })
        self.assertEqual(len(result["discovery_events"]), 5000)

    def test_rejects_unknown_format(self):
        with self.assertRaisesRegex(ValueError, "Unsupported session format"):
            validate_session_payload({"session_format": "future-format", "packets": []})

    def test_rejects_malformed_packet_before_restore(self):
        bad = packet(); bad.pop("records")
        with self.assertRaisesRegex(ValueError, "missing required fields: records"):
            validate_session_payload({"packets": [packet(), bad]})

    def test_rejects_invalid_nested_record(self):
        bad = packet(); bad["records"] = [{"type": "PTR"}]
        with self.assertRaisesRegex(ValueError, "without a text name or type"):
            validate_session_payload({"packets": [bad]})

    def test_rejects_oversized_session(self):
        with self.assertRaisesRegex(ValueError, "100,000 packets"):
            validate_session_payload({"packets": [None] * 100001})

    def test_rejects_non_list_discovery_state(self):
        with self.assertRaisesRegex(ValueError, "active_discoveries.*must be a list"):
            validate_session_payload({"packets": [], "active_discoveries": {}})

    def test_rejects_non_text_record_identity(self):
        bad = packet(); bad["records"] = [{"name": 42, "type": "A", "value": "192.0.2.2"}]
        with self.assertRaisesRegex(ValueError, "text name or type"):
            validate_session_payload({"packets": [bad]})

    def test_rejects_invalid_truncation_marker(self):
        with self.assertRaisesRegex(ValueError, "packet_history_truncated.*true or false"):
            validate_session_payload({"packets": [], "packet_history_truncated": "false"})

    def test_rejects_negative_ttl(self):
        bad = packet(); bad["records"] = [{"name": "host.local", "type": "A", "value": "192.0.2.2", "ttl": -1}]
        with self.assertRaisesRegex(ValueError, "negative record TTL"):
            validate_session_payload({"packets": [bad]})


if __name__ == "__main__":
    unittest.main()

class SessionRoundTripTests(unittest.TestCase):
    def test_json_round_trip_preserves_packet_evidence(self):
        import json
        original = {
            "session_format": "mdns-observatory-session-v1",
            "application_version": "1.7.0",
            "packets": [packet()],
            "active_discoveries": [{"instance": "Living Room._airplay._tcp.local", "port": 7000}],
            "discovery_events": [{"event": "added", "instance": "Living Room._airplay._tcp.local"}],
            "intended_rules": [{"service": "_airplay._tcp.local", "action": "allow"}],
            "packet_history_truncated": False,
        }
        restored = validate_session_payload(json.loads(json.dumps(original)))
        self.assertEqual(restored["packets"], original["packets"])
        self.assertEqual(restored["active_discoveries"], original["active_discoveries"])
        self.assertEqual(restored["discovery_events"], original["discovery_events"])
        self.assertEqual(restored["intended_rules"], original["intended_rules"])
        self.assertFalse(restored["packet_history_truncated"])

    def test_rejects_invalid_record_collection_types(self):
        bad = packet()
        bad["records"] = "not-a-list"
        with self.assertRaisesRegex(ValueError, "invalid questions, records"):
            validate_session_payload({"packets": [bad]})


class RestoredDiagnosticsTests(unittest.TestCase):
    def test_packet_count_matches_replayed_history_not_original_total(self):
        restored = restore_diagnostics({
            "frames_seen": 120000,
            "mdns_packets_accepted": 105000,
            "packet_history_truncated": 5000,
            "import_decode_errors": 2,
        }, 100000)
        self.assertEqual(restored["mdns_packets_accepted"], 100000)
        self.assertEqual(restored["frames_seen"], 120000)
        self.assertEqual(restored["packet_history_truncated"], 5000)
        self.assertEqual(restored["import_decode_errors"], 2)

    def test_invalid_diagnostic_values_are_ignored(self):
        restored = restore_diagnostics({"frames_seen": "lots", "decode_errors": -1}, 3)
        self.assertEqual(restored, {"mdns_packets_accepted": 3})
