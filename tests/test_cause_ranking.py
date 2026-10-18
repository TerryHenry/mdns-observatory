import unittest
from cause_ranking import rank_likely_causes

class CauseRankingTests(unittest.TestCase):
    def setUp(self):
        self.packets = [
            {"time":"2026-10-16T10:00:00", "direction":"Query", "source":"10.0.0.10", "destination":"224.0.0.251", "records":[], "summary":"_airplay._tcp.local PTR"},
            {"time":"2026-10-16T10:00:01", "direction":"Response", "source":"10.0.0.20", "destination":"224.0.0.251", "records":[{"name":"_airplay._tcp.local", "type":"PTR", "value":"Den TV._airplay._tcp.local"}, {"name":"Den TV._airplay._tcp.local", "type":"SRV", "value":"tv.local:7000"}], "summary":"AirPlay PTR SRV"},
        ]
    def test_query_without_response_ranks_exchange_visibility(self):
        result = rank_likely_causes(self.packets[:1], "client_cannot_discover", "airplay")
        self.assertTrue(result["causes"])
        self.assertIn("response", result["causes"][0]["cause"].lower())
        self.assertEqual(result["causes"][0]["evidence_indices"], [0])
    def test_query_and_response_supports_partial_exchange(self):
        result = rank_likely_causes(self.packets, "client_cannot_discover", "airplay")
        self.assertTrue(any("partly visible" in c["cause"] for c in result["causes"]))
        self.assertTrue(all(0 <= c["score"] <= 100 for c in result["causes"]))
    def test_empty_filter_result_is_visibility_caveat(self):
        result = rank_likely_causes(self.packets, "general", "printer", "192.0.2.5")
        self.assertEqual(result["matched_count"], 0)
        self.assertIn("Capture point", result["causes"][0]["cause"])
    def test_cross_vlan_recommends_dual_capture(self):
        result = rank_likely_causes(self.packets, "cross_vlan")
        self.assertTrue(any("forwarded or reflected" in c["cause"] for c in result["causes"]))
        self.assertTrue(any("both VLANs" in c["next_test"] for c in result["causes"]))
    def test_cause_order_is_deterministic(self):
        a = rank_likely_causes(self.packets, "service_not_resolving")
        b = rank_likely_causes(self.packets, "service_not_resolving")
        self.assertEqual([(x["rank"], x["cause"], x["score"]) for x in a["causes"]], [(x["rank"], x["cause"], x["score"]) for x in b["causes"]])
        self.assertIn("not statistical probabilities", a["caveat"])

if __name__ == "__main__": unittest.main()
