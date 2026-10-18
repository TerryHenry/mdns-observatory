#!/usr/bin/env python3
"""Run against the supplied regression capture: python tests/test_capture_regression.py /path/to/mdnssearch.pcapng"""
import sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from mdns_core import read_capture, decode_frame

def main():

    if len(sys.argv)<2:
        raise SystemExit('Usage: python tests/test_capture_regression.py /path/to/mdnssearch.pcapng')
    path=sys.argv[1]
    frames=0; packets=[]; linktypes=Counter(); errors=[]
    for ts,linktype,frame in read_capture(path):
        frames+=1; linktypes[linktype]+=1
        try:
            item=decode_frame(frame,linktype,ts)
            if item: packets.append(item)
        except Exception as exc: errors.append((frames,str(exc)))
    responses=[p for p in packets if p['direction']=='Response']
    records=[r for p in packets for r in p['records']]
    services=sorted({r['name'] for r in records if r['name'].endswith('._tcp.local') or r['name'].endswith('._udp.local')})
    service_families=sorted({name.split('._',1)[-1] for name in services if '._' in name and (name.endswith('._tcp.local') or name.endswith('._udp.local'))})
    print(f'Frames: {frames}')
    print(f'Link types: {dict(linktypes)}')
    print(f'mDNS packets: {len(packets)}')
    print(f'Queries/responses: {len(packets)-len(responses)}/{len(responses)}')
    print(f'Record types: {dict(Counter(r["type"] for r in records))}')
    print('Service types:')
    for s in services: print('  '+s)
    print(f'Service families: {service_families}')
    print(f'Decode errors: {len(errors)}')
    if errors: print('First errors:',errors[:5])
    assert frames==2713, f'Expected 2713 frames, got {frames}'
    assert len(packets)==9, f'Expected 9 mDNS packets, got {len(packets)}'
    assert len(responses)==1, f'Expected one mDNS response, got {len(responses)}'
    assert len(records)>=20, f'Expected response records, got {len(records)} total records'
    assert not errors, f'Decode errors occurred: {errors[:3]}'
    assert {'raop._tcp.local','airplay._tcp.local','googlecast._tcp.local'}.issubset(set(service_families)), f'Missing expected service families: {service_families}'
    print('PASS: supplied capture regression checks passed')

if __name__ == "__main__":
    main()
