import unittest
from capture_quality import assess_capture_quality, format_capture_quality


class CaptureQualityTests(unittest.TestCase):
    def codes(self, **kwargs):
        return {x['code'] for x in assess_capture_quality(**kwargs)['findings']}

    def test_live_capture_with_no_frames_is_cautious_warning(self):
        result = assess_capture_quality(capture_started='2026-01-01T00:00:00', diagnostics={})
        finding = result['findings'][0]
        self.assertEqual(finding['code'], 'no_frames')
        self.assertIn('does not establish', finding['detail'])

    def test_frames_without_mdns_are_not_called_a_failure(self):
        result = assess_capture_quality(diagnostics={'frames_seen': 123}, capture_started=True)
        self.assertEqual(result['findings'][0]['code'], 'no_mdns_observed')
        self.assertIn('may simply mean', result['findings'][0]['detail'])

    def test_positive_mdns_evidence(self):
        result = assess_capture_quality(diagnostics={'frames_seen': 80, 'mdns_packets_accepted': 4})
        self.assertIn('mdns_observed', {x['code'] for x in result['findings']})

    def test_decode_misses_and_truncation_are_reported(self):
        self.assertTrue({'decode_misses', 'history_truncated'} <= self.codes(
            diagnostics={'frames_seen': 5, 'live_port_5353_not_decoded': 2}, packet_history_truncated=True))

    def test_capture_error_and_render(self):
        result = assess_capture_quality(capture_error='Permission denied\nmore detail')
        self.assertIn('capture_error', {x['code'] for x in result['findings']})
        self.assertIn('CAPTURE QUALITY TRIAGE', format_capture_quality(result))


if __name__ == '__main__':
    unittest.main()
