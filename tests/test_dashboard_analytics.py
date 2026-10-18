import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dashboard_analytics import mac_manufacturer, packet_manufacturer

class DashboardAnalyticsTests(unittest.TestCase):
    def test_known_apple_oui(self):
        self.assertEqual(mac_manufacturer("f0:18:98:12:34:56"), "Apple")
    def test_additional_apple_oui(self):
        self.assertEqual(mac_manufacturer("a8:5c:2c:12:34:56"), "Apple")
    def test_locally_administered_mac_is_not_guessed(self):
        self.assertEqual(mac_manufacturer("02:11:22:33:44:55"), "Private / randomized MAC")
    def test_missing_mac_is_unknown(self):
        self.assertEqual(mac_manufacturer(""), "Unknown / unavailable")
    def test_normalized_hyphen_mac(self):
        self.assertEqual(mac_manufacturer("00-00-0c-12-34-56"), "Cisco")

    def test_randomized_mac_with_explicit_iphone_hostname(self):
        self.assertEqual(packet_manufacturer("02:11:22:33:44:55", "192.0.2.20",
                         {"192.0.2.20": "Johns-iPhone.local"}), "Apple (hostname inferred)")

    def test_service_type_alone_does_not_infer_apple(self):
        self.assertNotEqual(packet_manufacturer("02:11:22:33:44:55", "192.0.2.20", {},
                         [{"name": "_airplay._tcp.local", "value": "Living Room"}], []), "Apple (hostname inferred)")

if __name__ == "__main__":
    unittest.main()
