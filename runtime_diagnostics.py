"""Runtime and capture-environment diagnostics for support bundles and UI."""
import importlib.metadata
import platform
import sys


def runtime_diagnostics(*, app_version, interfaces=(), selected_interface="", capture_error="", discovery_errors=(), scapy_available=None):
    def version(package):
        try:
            return importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            return "not installed"
        except Exception as exc:
            return f"unknown ({exc})"

    if scapy_available is None:
        try:
            import scapy  # noqa: F401
            scapy_available = True
        except Exception:
            scapy_available = False
    return {
        "app_version": str(app_version),
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python": sys.version.split()[0],
        "python_executable": sys.executable,
        "frozen_bundle": bool(getattr(sys, "frozen", False)),
        "scapy_available": bool(scapy_available),
        "scapy_version": version("scapy"),
        "pyside6_version": version("PySide6"),
        "interface_count": len(list(interfaces or [])),
        "interfaces": [str(x) for x in interfaces or []],
        "selected_interface": str(selected_interface or "Default interface"),
        "capture_error": str(capture_error or "None"),
        "discovery_error_count": len(list(discovery_errors or [])),
        "discovery_errors": [str(x)[:500] for x in list(discovery_errors or [])[-10:]],
    }


def format_runtime_diagnostics(data):
    labels = [
        ("app_version", "Application"), ("os", "Operating system"),
        ("python", "Python"), ("python_executable", "Python executable"),
        ("frozen_bundle", "Packaged app"), ("scapy_available", "Scapy available"),
        ("scapy_version", "Scapy version"), ("pyside6_version", "PySide6 version"),
        ("interface_count", "Interfaces found"), ("selected_interface", "Selected interface"),
        ("capture_error", "Last capture error"), ("discovery_error_count", "Bonjour errors"),
    ]
    lines = [f"{label}: {data.get(key, 'unknown')}" for key, label in labels]
    lines += ["", "Available interfaces:"]
    lines += [f"  • {name}" for name in data.get("interfaces", [])] or ["  (none reported)"]
    errors = data.get("discovery_errors", [])
    if errors:
        lines += ["", "Recent Bonjour errors:"] + [f"  • {error}" for error in errors]
    lines += ["", "Privacy: diagnostics include local interface names and error text. Review before sharing."]
    return "\n".join(lines)
