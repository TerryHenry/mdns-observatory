# mDNS Observatory

A macOS-focused desktop application for observing and troubleshooting multicast DNS (mDNS) and DNS-Based Service Discovery (DNS-SD).

## v2.22.0

- Time-windowed analysis of discovery queries and matching response candidates.
- Recurring query pattern grouping across capture-relative time windows.
- Plain-language findings and guided troubleshooting.
- DNS-SD service relationship analysis, capture-quality diagnostics, packet investigation, and capture comparison.
- Evidence drill-down to supporting packets.

This tool analyzes what was observed in a capture. A candidate response does not prove a client received a multicast response or that an application worked. A missing response or service record is not proof that a service is down.

## Run on macOS

1. Download or clone this repository.
2. Install Python 3 and the dependencies in `requirements.txt`.
3. Run `START-MAC.command` to launch from source.
4. Or run `BUILD-MAC-APP.command` to build `dist/mDNS Observatory.app`.

The native app bundle is not code-signed or notarized. macOS may display a security prompt; inspect the source before running.

## Tests

Compile the source and tests:

```bash
python3 -m py_compile *.py tests/*.py
```

Run the regression suite with a capture file:

```bash
python3 tests/run_regression_suite.py /path/to/capture.pcapng
```

## Privacy

Captures and reports may contain hostnames, service names, MAC/IP addresses, and other network metadata. Review evidence before sharing. Avoid committing packet captures, support bundles, credentials, or live network data.

## Version

Current packaged source: **v2.22.0**.
