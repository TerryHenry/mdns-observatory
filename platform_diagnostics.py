"""Portable, testable diagnostics for capture and bundled-resource failures."""
from pathlib import Path
import sys


def resource_path(name, script_file=None):
    """Resolve bundled resources in source runs and PyInstaller bundles."""
    name = str(name)
    roots = []
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root:
        roots.append(Path(bundle_root))
    if script_file:
        roots.append(Path(script_file).resolve().parent)
    roots.append(Path.cwd())
    for root in roots:
        candidate = root / name
        if candidate.is_file():
            return candidate
    # Return the most likely bundle/source location so callers can report it.
    return (roots[0] if roots else Path.cwd()) / name


def capture_error_guidance(message, platform=None):
    """Append actionable, platform-specific hints without hiding the raw error."""
    raw = str(message or "Unknown capture error").strip() or "Unknown capture error"
    lower = raw.lower()
    platform = platform or sys.platform
    hints = []
    if any(token in lower for token in ("permission", "operation not permitted", "access denied", "bpf")):
        if platform == "darwin":
            hints.append("macOS may be blocking packet capture. Try launching from Terminal and verify the user has permitted access to the capture device. Do not change /dev/bpf permissions globally.")
        elif platform.startswith("linux"):
            hints.append("Check packet-capture capabilities or run with an approved capture permission method. Avoid running the GUI as root unless your security policy permits it.")
        else:
            hints.append("Check the operating system's packet-capture permissions and security software.")
    if any(token in lower for token in ("no such device", "interface", "network interface")):
        hints.append("Refresh the interface list and select an interface that is currently connected and supports packet capture.")
    if "libpcap" in lower or "pcap" in lower:
        hints.append("Verify that Scapy and the platform's packet-capture backend are installed and available to this Python environment.")
    if not hints:
        hints.append("Check the selected interface, packet-capture backend, and application diagnostics before retrying.")
    return raw + "\n\n" + "\n".join(hints)
