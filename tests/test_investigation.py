import unittest
from investigation import build_timeline, correlate_queries_responses, build_prioritized_findings, build_investigation

class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.packets = [
            {'time':'2026-01-01T00:00:00+00:00','timestamp':1767225600.0,'source':'10.0.0.2','destination':'224.0.0.251','direction':'Query','questions':[{'name':'_demo._tcp.local','type':'PTR'}],'records':[]},
            {'time':'2026-01-01T00:00:01+00:00','timestamp':1767225601.0,'source':'10.0.0.3','destination':'224.0.0.251','direction':'Response','questions':[],'records':[{'name':'_demo._tcp.local','type':'PTR'}]},
        ]
    def test_timeline_buckets(self):
        result=build_timeline(self.packets,60)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]['packets'],2)
        self.assertEqual(result[0]['queries'],1)
    def test_query_response_candidate(self):
        result=correlate_queries_responses(self.packets)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]['responder'],'10.0.0.3')
        self.assertEqual(result[0]['confidence'],'Candidate match')
    def test_conflict_finding(self):
        rows=build_prioritized_findings(self.packets,[{'instance':'demo','conflicts':['different SRV ports'],'target':'host','addresses':['10.0.0.3']}],[])
        self.assertEqual(rows[0]['priority'],'High')
    def test_empty_capture_finding(self):
        result=build_investigation([],[],[])
        self.assertEqual(result['findings'][0]['finding'],'No retained packet evidence')

if __name__=='__main__': unittest.main()
