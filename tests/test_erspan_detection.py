import socket
import struct
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mdns_core import decode_frame, DLT_EN10MB


def ethernet_ipv4_udp_mdns():
    # Ethernet / IPv4 / UDP 5353 / one PTR question: _services._dns-sd._udp.local
    qname = b''.join(bytes([len(x)]) + x for x in (b'_services', b'_dns-sd', b'_udp', b'local')) + b'\x00'
    dns = struct.pack('!HHHHHH', 0, 0, 1, 0, 0, 0) + qname + struct.pack('!HH', 12, 1)
    udp = struct.pack('!HHHH', 5353, 5353, 8 + len(dns), 0) + dns
    src = socket.inet_aton('192.0.2.10'); dst = socket.inet_aton('224.0.0.251')
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 255, 17, 0, src, dst)
    eth = bytes.fromhex('01005e0000fb0011223344550800')
    return eth + ip + udp


def erspan_wrap(inner, proto):
    outer_src = socket.inet_aton('198.51.100.1'); outer_dst = socket.inet_aton('198.51.100.2')
    # GRE flags/version 0, ERSPAN protocol type.
    gre = struct.pack('!HH', 0, proto)
    erspan = (b'\x00' * (8 if proto == 0x88be else 12))
    payload = gre + erspan + inner
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 2, 0, 64, 47, 0, outer_src, outer_dst)
    eth = bytes.fromhex('0011223344550066778899aa0800')
    return eth + ip + payload


class ErspanDetectionTests(unittest.TestCase):
    def test_plain_mdns_is_classified_local(self):
        info = decode_frame(ethernet_ipv4_udp_mdns(), DLT_EN10MB, 1.0)
        self.assertIsNotNone(info)
        self.assertEqual(info['capture_origin'], 'local')

    def test_erspan_type_ii_is_unwrapped(self):
        info = decode_frame(erspan_wrap(ethernet_ipv4_udp_mdns(), 0x88be), DLT_EN10MB, 1.0)
        self.assertIsNotNone(info)
        self.assertEqual(info['capture_origin'], 'erspan')
        self.assertEqual(info['tunnel']['erspan_type'], 'II')
        self.assertEqual(info['source'], '192.0.2.10')

    def test_erspan_type_iii_is_unwrapped(self):
        info = decode_frame(erspan_wrap(ethernet_ipv4_udp_mdns(), 0x22eb), DLT_EN10MB, 1.0)
        self.assertIsNotNone(info)
        self.assertEqual(info['capture_origin'], 'erspan')
        self.assertEqual(info['tunnel']['erspan_type'], 'III')

    def test_erspan_over_raw_ipv4_is_unwrapped(self):
        from mdns_core import DLT_RAW
        wrapped = erspan_wrap(ethernet_ipv4_udp_mdns(), 0x88be)
        info = decode_frame(wrapped[14:], DLT_RAW, 1.0)
        self.assertIsNotNone(info)
        self.assertEqual(info['capture_origin'], 'erspan')
        self.assertEqual(info['source'], '192.0.2.10')

if __name__ == '__main__':
    unittest.main()
