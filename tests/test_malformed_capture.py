"""Regression tests for malformed/truncated PCAPNG block handling."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mdns_core import read_capture


def block(block_type, body):
    total = 12 + len(body)
    return struct.pack('<II', block_type, total) + body + struct.pack('<I', total)


def pcapng_prefix():
    # Section Header Block, little-endian, followed by an Ethernet interface.
    shb = (struct.pack('<I I I H H q I', 0x0A0D0D0A, 28, 0x1A2B3C4D,
                       1, 0, -1, 28))
    idb_body = struct.pack('<H H I', 1, 0, 65535) + struct.pack('<H H', 0, 0)
    idb = block(1, idb_body)
    return shb + idb


class MalformedCaptureTests(unittest.TestCase):
    def read_bytes(self, content):
        with tempfile.NamedTemporaryFile(suffix='.pcapng', delete=False) as f:
            f.write(content)
            path = f.name
        try:
            return list(read_capture(path))
        finally:
            Path(path).unlink(missing_ok=True)

    def test_rejects_enhanced_packet_with_truncated_frame(self):
        epb_body = struct.pack('<IIIII', 0, 0, 1, 20, 20) + b'ABCD'
        with self.assertRaisesRegex(ValueError, 'truncated frame data'):
            self.read_bytes(pcapng_prefix() + block(6, epb_body))

    def test_rejects_captured_length_larger_than_original(self):
        epb_body = struct.pack('<IIIII', 0, 0, 1, 4, 2) + b'ABCD'
        with self.assertRaisesRegex(ValueError, 'exceeds original frame length'):
            self.read_bytes(pcapng_prefix() + block(6, epb_body))


    def test_rejects_classic_pcap_captured_length_larger_than_original(self):
        header = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 1)
        record = struct.pack('<IIII', 1, 0, 4, 2) + b'ABCD'
        with self.assertRaisesRegex(ValueError, 'exceeds original packet length'):
            self.read_bytes(header + record)

    def test_rejects_classic_pcap_packet_over_snaplen(self):
        header = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 2, 1)
        record = struct.pack('<IIII', 1, 0, 4, 4) + b'ABCD'
        with self.assertRaisesRegex(ValueError, 'exceeds interface snap length'):
            self.read_bytes(header + record)

    def test_rejects_classic_pcap_oversized_record_before_reading_payload(self):
        header = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 0, 1)
        record = struct.pack('<IIII', 1, 0, 64 * 1024 * 1024 + 1, 64 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ValueError, '64 MiB safety limit'):
            self.read_bytes(header + record)

    def test_rejects_bad_section_header_trailer(self):
        shb = bytearray(struct.pack('<I I I H H q I', 0x0A0D0D0A, 28, 0x1A2B3C4D,
                                    1, 0, -1, 28))
        shb[-4:] = struct.pack('<I', 24)
        with self.assertRaisesRegex(ValueError, 'section header length trailer mismatch'):
            self.read_bytes(bytes(shb))

    def test_simple_packet_block_allows_snaplen_truncation(self):
        # Original packet is 100 bytes, but only four captured bytes are present.
        spb_body = struct.pack('<I', 100) + b'ABCD'
        result = self.read_bytes(pcapng_prefix() + block(3, spb_body))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][2], b'ABCD')


if __name__ == '__main__':
    unittest.main()
