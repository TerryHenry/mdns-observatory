import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from flow_analysis import filter_flow_packets, packet_service_types

class FlowFilterTests(unittest.TestCase):
    def setUp(self):
        self.packets = [
            {"timestamp": 1000, "source": "192.168.1.10", "destination": "224.0.0.251", "questions": [{"name": "_airplay._tcp.local.", "type": "PTR"}], "records": [], "services": []},
            {"timestamp": 1100, "source": "192.168.1.20", "destination": "224.0.0.251", "questions": [], "records": [{"name": "_googlecast._tcp.local.", "type": "PTR"}], "services": []},
            {"timestamp": 1500, "source": "192.168.1.10", "destination": "192.168.1.20", "questions": [], "records": [{"name": "_airplay._tcp.local.", "type": "SRV"}], "services": []},
        ]

    def test_ip_filter_matches_source_or_destination(self):
        self.assertEqual(len(filter_flow_packets(self.packets, ip_filter="192.168.1.20")), 2)

    def test_multicast_filter(self):
        self.assertEqual(len(filter_flow_packets(self.packets, multicast_group="224.0.0.251")), 2)

    def test_service_type_filter(self):
        self.assertEqual(len(filter_flow_packets(self.packets, service_type="_airplay._tcp.local")), 2)

    def test_time_range_relative_to_newest_capture_timestamp(self):
        self.assertEqual(len(filter_flow_packets(self.packets, minutes=1)), 1)

    def test_service_types_are_normalized(self):
        types = packet_service_types({"records": [{"name": "_AirPlay._TCP.local."}]})
        self.assertEqual(types, {"_airplay._tcp.local"})

if __name__ == "__main__":
    unittest.main()
