# mDNS Observatory

**Current version: 2.24.20** · desktop app for observing and troubleshooting multicast DNS (mDNS) and DNS-Based Service Discovery (DNS-SD) on macOS and Windows.

mDNS Observatory combines passive packet analysis with active Bonjour browsing. Import a PCAP/PCAPNG or capture on a local interface, then explore devices, service instances, DNS records, and packet evidence in linked dashboard workspaces.

## Highlights

- Dashboard summaries, time windows, chart drilldowns, and customizable panel layouts.
- Live packet capture and PCAP/PCAPNG import, including ERSPAN-decapsulated mDNS evidence.
- Service and device inspectors with explanations grounded in observed PTR, SRV, TXT, A, and AAAA records.
- Bundled community-maintained DNS-SD service catalog, searchable offline and refreshable in the app.
- Active Bonjour discovery from the dashboard, separate from passive capture.
- Session save/open and report export.

## Get the app

Download the Apple Silicon macOS build or Windows x64 build from the [v2.24.20 GitHub release](https://github.com/TerryHenry/mdns-observatory/releases/tag/v2.24.20). Neither application is code-signed. macOS may show a security prompt; Windows may show SmartScreen.

## Run from source

1. Clone this repository and install Python 3 on macOS.
2. Run `START-MAC.command` to launch the app from source. The launcher prepares an isolated environment using the project requirements.
3. Run `BUILD-MAC-APP.command` to build `dist/mDNS Observatory.app`.

See the [User Guide](docs/mDNS-Observatory-User-Guide-v2.24.20.docx) for capture, import, dashboard, DNS-SD, catalog, and discovery workflows.

## Windows support

Windows supports PCAP/PCAPNG analysis and passive live capture. Install [Npcap](https://npcap.com/) to enable live packet capture; PCAP file analysis does not require Npcap. Active Bonjour browsing currently uses Apple's native DNS-SD library and is available on macOS only. The Windows app disables that control and explains the limitation.

To build on Windows, use Python 3.12, install `requirements.txt` and PyInstaller, then package `mdns_snooper.py` with the service catalogs and `THIRD_PARTY_NOTICES.md`. The GitHub Actions workflow builds the Windows x64 release asset on a Windows runner.

## Service catalog

The app combines curated explanations with the community-maintained `bbusse/mdns-discover` reference. Curated app entries take precedence when descriptions overlap. Catalog matches are informational: they do not prove a device's identity or that a service was used successfully. Upstream attribution and license details are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Evidence and privacy

This tool describes what was observed in a capture. An advertised service does not prove that a client connected, and a missing record does not prove that a service is unavailable. Captures and reports can contain hostnames, service names, MAC/IP addresses, and other network metadata. Review them before sharing. Do not commit packet captures, support bundles, credentials, or live network data.

## Tests

Compile source and tests:

```bash
python3 -m py_compile *.py tests/*.py
```

Run the regression suite with a capture file:

```bash
python3 tests/run_regression_suite.py /path/to/capture.pcapng
```

