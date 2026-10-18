import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from platform_diagnostics import resource_path, capture_error_guidance

class PlatformDiagnosticsTests(unittest.TestCase):
    def test_resource_path_finds_source_resource(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "service_catalog.json").write_text("[]", encoding="utf-8")
            self.assertEqual(resource_path("service_catalog.json", root / "main.py"), root / "service_catalog.json")

    def test_resource_path_prefers_frozen_bundle_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "catalog.json").write_text("{}", encoding="utf-8")
            with patch.object(sys, "_MEIPASS", str(root), create=True):
                self.assertEqual(resource_path("catalog.json", "/missing/main.py"), root / "catalog.json")

    def test_macos_permission_guidance_avoids_global_bpf_chmod(self):
        result = capture_error_guidance("Operation not permitted opening /dev/bpf", "darwin")
        self.assertIn("macOS may be blocking", result)
        self.assertIn("Do not change /dev/bpf permissions globally", result)

    def test_libpcap_guidance_is_actionable(self):
        self.assertIn("Scapy", capture_error_guidance("libpcap backend unavailable", "darwin"))

    def test_unknown_error_retains_original_text(self):
        result = capture_error_guidance("socket initialization failed", "darwin")
        self.assertTrue(result.startswith("socket initialization failed"))
        self.assertIn("Check the selected interface", result)

if __name__ == "__main__":
    unittest.main()
