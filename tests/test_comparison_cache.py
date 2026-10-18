import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from comparison_cache import comparison_cache_key, discovery_signature


class ComparisonCacheTests(unittest.TestCase):
    def test_key_changes_when_analyzer_generation_changes(self):
        row = [{"instance": "Speaker._airplay._tcp.local", "host": "speaker.local", "port": 7000}]
        self.assertNotEqual(comparison_cache_key(1, 4, row), comparison_cache_key(1, 5, row))

    def test_key_changes_when_active_result_changes(self):
        a = [{"instance": "Speaker._airplay._tcp.local", "host": "speaker.local", "port": 7000}]
        b = [{"instance": "Speaker._airplay._tcp.local", "host": "speaker.local", "port": 7001}]
        self.assertNotEqual(comparison_cache_key(1, 4, a), comparison_cache_key(1, 4, b))

    def test_signature_is_order_independent(self):
        a = [{"instance": "A._http._tcp.local"}, {"instance": "B._http._tcp.local"}]
        b = list(reversed(a))
        self.assertEqual(discovery_signature(a), discovery_signature(b))

    def test_dns_names_are_normalized_but_port_is_not(self):
        a = [{"instance": "Printer._ipp._tcp.local.", "host": "PRINTER.local.", "port": 631}]
        b = [{"instance": "printer._ipp._tcp.local", "host": "printer.local", "port": 631}]
        c = [{"instance": "printer._ipp._tcp.local", "host": "printer.local", "port": 632}]
        self.assertEqual(discovery_signature(a), discovery_signature(b))
        self.assertNotEqual(discovery_signature(a), discovery_signature(c))


if __name__ == "__main__":
    unittest.main()
