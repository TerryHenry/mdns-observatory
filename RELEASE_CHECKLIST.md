# Release checklist — v2.24.20

## Included in this release

- Searchable community-maintained DNS-SD catalog with in-app update workflow.
- Curated service explanations take precedence over community descriptions.
- Dashboard discovery control, named drilldown navigation, service/device explanations, and DNS-SD help.
- PCAP/PCAPNG import and passive capture with ERSPAN-aware evidence handling.
- User guide at `docs/mDNS-Observatory-User-Guide-v2.24.20.docx`.

## Verify before publishing a new build

- [ ] Validate import of representative PCAP and PCAPNG files, including a capture containing mDNS frames.
- [ ] Confirm capture-source filtering and ERSPAN-decapsulated traffic on the target Mac and network adapter.
- [ ] Confirm active Bonjour discovery starts/stops and remains distinct from passive packet capture.
- [ ] Refresh the community catalog; verify validation, preview, approval, and offline use.
- [ ] Review service/device explanations against observed PTR, SRV, TXT, A, and AAAA evidence.
- [ ] Confirm session save/open and report export.
- [ ] Build and launch the app on native Apple Silicon macOS.
- [ ] Review the final release asset and notes; the app bundle is not signed or notarized.

Do not commit packet captures, support bundles, credentials, or live network data.
