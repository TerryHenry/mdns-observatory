import unittest
from guided_troubleshooting import analyze_guided_issue, SYMPTOMS

class GuidedTroubleshootingTests(unittest.TestCase):
    def setUp(self):
        self.packets = [
            {"time":"2026-10-16T10:00:00", "direction":"Query", "source":"10.0.0.10", "destination":"224.0.0.251", "records":[], "summary":"_airplay._tcp.local PTR"},
            {"time":"2026-10-16T10:00:01", "direction":"Response", "source":"10.0.0.20", "destination":"224.0.0.251", "records":[{"name":"_airplay._tcp.local", "type":"PTR", "value":"Den TV._airplay._tcp.local"}], "summary":"AirPlay PTR"},
        ]
    def test_filters_service_and_client(self):
        r = analyze_guided_issue(self.packets, "client_cannot_discover", "airplay", "10.0.0.10")
        self.assertEqual(r["evidence_indices"], [0])
        self.assertTrue(r["steps"])
    def test_no_matches_is_not_outage_claim(self):
        r = analyze_guided_issue(self.packets, "general", "printer", "192.0.2.1")
        self.assertEqual(r["matched_count"], 0)
        self.assertIn("not proof", r["steps"][1]["evidence"].lower())
    def test_evidence_references_are_stable_indices(self):
        r = analyze_guided_issue(self.packets)
        self.assertEqual([x["index"] for x in r["evidence"]], [0, 1])
    def test_supported_symptoms(self):
        self.assertGreaterEqual(len(SYMPTOMS), 5)
        for symptom, _ in SYMPTOMS:
            self.assertEqual(analyze_guided_issue(self.packets, symptom)["symptom"], symptom)

if __name__ == "__main__": unittest.main()
