import unittest
from flow_analysis import build_flow_summary

class FlowAnalysisTests(unittest.TestCase):
    def test_aggregates_source_destination_and_classifies_multicast(self):
        packets = [
            {"source":"192.0.2.10", "destination":"224.0.0.251", "direction":"Query", "time":"2026-01-01T10:00:00"},
            {"source":"192.0.2.10", "destination":"224.0.0.251", "direction":"Response", "time":"2026-01-01T10:00:02"},
            {"source":"192.0.2.20", "destination":"192.0.2.10", "direction":"Query", "time":"2026-01-01T10:00:03"},
        ]
        result = build_flow_summary(packets)
        self.assertEqual(result["rows"][0][3], 2)
        self.assertEqual(result["rows"][0][2], "Multicast group")
        unicast = next(row for row in result["rows"] if row[1] == "192.0.2.10")
        self.assertEqual(unicast[2], "Observed unicast")
        self.assertEqual(unicast[4], 1)

    def test_empty_capture(self):
        self.assertEqual(build_flow_summary([])["rows"], [])

if __name__ == "__main__": unittest.main()
