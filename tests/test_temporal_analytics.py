import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from temporal_analytics import analyze_temporal_discovery

class TemporalAnalyticsTests(unittest.TestCase):
    def test_candidate_response_and_unanswered_query(self):
        packets = [
            {'time':'2026-10-16T10:00:00+00:00','direction':'Query','source':'10.0.0.2','questions':[{'name':'_demo._tcp.local','type':'PTR'}]},
            {'time':'2026-10-16T10:00:01+00:00','direction':'Response','source':'10.0.0.3','records':[{'name':'_demo._tcp.local','type':'PTR','value':'Printer._demo._tcp.local'}]},
            {'time':'2026-10-16T10:00:20+00:00','direction':'Query','source':'10.0.0.4','questions':[{'name':'_missing._tcp.local','type':'PTR'}]},
        ]
        result = analyze_temporal_discovery(packets)
        self.assertEqual(result['summary']['candidate_answered'], 1)
        self.assertEqual(result['summary']['no_candidate'], 1)
        self.assertEqual(result['queries'][0]['response_candidates'][0]['index'], 1)

    def test_recurring_concern_requires_multiple_windows(self):
        packets = [
            {'time':'2026-10-16T10:00:00+00:00','direction':'Query','source':'10.0.0.2','questions':[{'name':'_demo._tcp.local','type':'PTR'}]},
            {'time':'2026-10-16T10:01:10+00:00','direction':'Query','source':'10.0.0.2','questions':[{'name':'_demo._tcp.local','type':'PTR'}]},
        ]
        result = analyze_temporal_discovery(packets)
        self.assertEqual(result['patterns'][0]['classification'], 'Recurring concern')
        self.assertEqual(result['patterns'][0]['windows_seen'], 2)

    def test_single_window_burst_not_called_persistent(self):
        packets = [
            {'time':'2026-10-16T10:00:00+00:00','direction':'Query','source':'10.0.0.2','questions':[{'name':'_demo._tcp.local','type':'PTR'}]},
            {'time':'2026-10-16T10:00:02+00:00','direction':'Query','source':'10.0.0.2','questions':[{'name':'_demo._tcp.local','type':'PTR'}]},
        ]
        result = analyze_temporal_discovery(packets)
        self.assertEqual(result['patterns'][0]['classification'], 'Single-window burst')

    def test_missing_timestamps_is_explicitly_unavailable(self):
        result = analyze_temporal_discovery([{'direction':'Query','questions':[]}])
        self.assertFalse(result['available'])

if __name__ == '__main__':
    unittest.main()
