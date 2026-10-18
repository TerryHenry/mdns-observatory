import sys
import time
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from packet_history import append_bounded, MAX_PACKET_HISTORY

class PacketHistoryTests(unittest.TestCase):
    def test_preserves_order_and_hard_limit(self):
        packets = []
        removed = 0
        for i in range(MAX_PACKET_HISTORY + 1234):
            removed += append_bounded(packets, i)
            self.assertLessEqual(len(packets), MAX_PACKET_HISTORY)
        self.assertEqual(packets, list(range(MAX_PACKET_HISTORY + 1234 - len(packets), MAX_PACKET_HISTORY + 1234)))
        self.assertEqual(removed + len(packets), MAX_PACKET_HISTORY + 1234)
        self.assertEqual(packets[-1], MAX_PACKET_HISTORY + 1233)

    def test_no_trim_under_limit(self):
        packets = []
        for i in range(100):
            self.assertEqual(append_bounded(packets, i, limit=100), 0)
        self.assertEqual(len(packets), 100)

    def test_invalid_limits_rejected(self):
        with self.assertRaises(ValueError):
            append_bounded([], 1, limit=0)

    def test_large_append_smoke_performance(self):
        packets = []
        start = time.perf_counter()
        for i in range(250_000):
            append_bounded(packets, i)
        elapsed = time.perf_counter() - start
        self.assertEqual(len(packets), MAX_PACKET_HISTORY)
        self.assertEqual(packets[-1], 249_999)
        # Broad guard against accidentally restoring O(n) slicing per packet.
        self.assertLess(elapsed, 8.0, f"250k appends unexpectedly slow: {elapsed:.2f}s")

if __name__ == '__main__':
    unittest.main()
