# mDNS Observatory v2.22.0 release checklist

- [ ] Run `python3 -m py_compile *.py tests/*.py`.
- [ ] Run `python3 tests/run_regression_suite.py /path/to/capture.pcapng`.
- [ ] Confirm temporal analytics distinguishes candidate response observations from no matching response observed.
- [ ] Confirm recurring patterns require repeated observations across multiple time windows.
- [ ] Confirm one-window bursts are not described as persistent problems.
- [ ] Double-click a temporal pattern and verify packet evidence opens in Live traffic.
- [ ] Confirm a capture without parseable timestamps shows a clear unavailable state.
- [ ] Launch on macOS using `START-MAC.command`.
- [ ] Build and launch `dist/mDNS Observatory.app` using `BUILD-MAC-APP.command`.
- [ ] Confirm all existing workspaces and session import/export still work.
