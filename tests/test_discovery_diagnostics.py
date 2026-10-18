import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from discovery_diagnostics import summarize_discovery_events

class DiscoveryDiagnosticsTests(unittest.TestCase):
    def test_counts_events_and_summarizes_errors(self):
        result = summarize_discovery_events([
            {"event": "add", "instance": "Speaker"},
            {"event": "error", "time": "now", "service_type": "_airplay._tcp", "error": "browse failed"},
            {"event": "resolve_error", "instance": "Printer", "error": "timeout"},
        ])
        self.assertEqual(result["event_counts"], {"add": 1, "error": 1, "resolve_error": 1})
        self.assertEqual(result["error_count"], 2)
        self.assertEqual(result["recent_errors"][0]["error"], "browse failed")

    def test_handles_empty_and_malformed_events(self):
        self.assertEqual(summarize_discovery_events([])["error_count"], 0)
        result = summarize_discovery_events([None, "bad", {"event": "error", "error": "x"}])
        self.assertEqual(result["error_count"], 1)

    def test_error_history_is_bounded_to_latest_twenty(self):
        events = [{"event": "error", "error": str(i)} for i in range(25)]
        result = summarize_discovery_events(events)
        self.assertEqual(result["error_count"], 25)
        self.assertEqual(len(result["recent_errors"]), 20)
        self.assertEqual(result["recent_errors"][0]["error"], "5")

if __name__ == "__main__":
    unittest.main()
