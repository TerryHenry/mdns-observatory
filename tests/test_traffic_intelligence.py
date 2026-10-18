"""Unit tests for dependency-free traffic intelligence heuristics."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from traffic_intelligence import build_traffic_intelligence

packets=[
 {"time":"2026-10-16T10:00:01-04:00","family":"IPv4","direction":"Query","source":"10.0.1.2","vlan":"10","questions":[{"name":"_ipp._tcp.local","type":"PTR"}],"records":[]},
 {"time":"2026-10-16T10:00:20-04:00","family":"IPv6","direction":"Query","source":"10.0.1.2","vlan":"10","questions":[{"name":"_ipp._tcp.local","type":"PTR"}],"records":[]},
 {"time":"2026-10-16T10:01:02-04:00","family":"IPv4","direction":"Response","source":"10.0.1.8","vlan":"20","questions":[],"records":[{"name":"printer.local","type":"A"}]},
]
result=build_traffic_intelligence(packets)
assert result['families']['IPv4']==2 and result['families']['IPv6']==1
assert result['directions']['Query']==2 and result['directions']['Response']==1
assert result['sources']['10.0.1.2']==2
assert result['vlans']['10']==2 and result['vlans']['20']==1
assert result['candidate_queries']==[('_ipp._tcp.local','PTR',2)]
assert len(result['minute_bins'])==2
print('PASS: traffic intelligence unit tests')
