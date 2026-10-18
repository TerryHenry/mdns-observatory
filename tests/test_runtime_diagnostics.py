import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runtime_diagnostics import runtime_diagnostics, format_runtime_diagnostics


class RuntimeDiagnosticsTests(unittest.TestCase):
    def test_report_contains_platform_interfaces_and_errors(self):
        data = runtime_diagnostics(app_version="2.15.0", interfaces=["en0", "lo0"], selected_interface="en0",
                                   capture_error="BPF permission denied", discovery_errors=["dns-sd failed"], scapy_available=True)
        rendered = format_runtime_diagnostics(data)
        self.assertEqual(data["interface_count"], 2)
        self.assertIn("en0", rendered)
        self.assertIn("BPF permission denied", rendered)
        self.assertIn("dns-sd failed", rendered)
        self.assertIn("Review before sharing", rendered)

    def test_handles_empty_optional_values(self):
        data = runtime_diagnostics(app_version="test", interfaces=None, discovery_errors=None, scapy_available=False)
        self.assertEqual(data["interface_count"], 0)
        self.assertEqual(data["discovery_error_count"], 0)
        self.assertIn("(none reported)", format_runtime_diagnostics(data))


if __name__ == "__main__":
    unittest.main()
