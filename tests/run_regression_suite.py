#!/usr/bin/env python3
"""Run dependency-free regression checks. Optionally pass a known PCAP/PCAPNG file."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
commands = [
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_session_io.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_packet_history.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_comparison_cache.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_discovery_diagnostics.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_platform_diagnostics.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_runtime_diagnostics.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_capture_quality.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_support_bundle.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_bonjour_lifecycle.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_report_data.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_malformed_capture.py'],
    [sys.executable, 'tests/test_service_correlation.py'],
    [sys.executable, 'tests/test_traffic_intelligence.py'],
    [sys.executable, 'tests/test_erspan_detection.py'],
    [sys.executable, 'tests/test_dashboard_analytics.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_flow_filters.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_investigation.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_capture_compare.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_guided_troubleshooting.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_cause_ranking.py'],
    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_temporal_analytics.py'],
]
if len(sys.argv) > 1:
    commands.append([sys.executable, 'tests/test_capture_regression.py', sys.argv[1]])
else:
    print('NOTE: no capture supplied; deterministic packet-capture regression was not run.')
for command in commands:
    print('\n>>>', ' '.join(command), flush=True)
    result = subprocess.run(command, cwd=ROOT)
    if result.returncode:
        raise SystemExit(result.returncode)
print('\nPASS: all configured mDNS Observatory regression checks passed')
