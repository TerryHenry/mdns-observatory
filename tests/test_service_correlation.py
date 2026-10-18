import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from service_correlation import build_service_chains


def test_correlates_split_dns_sd_chain():
    packets=[
        {"source":"10.0.0.2","records":[{"name":"_ipp._tcp.local","type":"PTR","value":"Office Printer._ipp._tcp.local."}]},
        {"source":"10.0.0.3","records":[{"name":"Office Printer._ipp._tcp.local","type":"SRV","value":"priority=0 weight=0 port=631 target=printer.local"},{"name":"Office Printer._ipp._tcp.local","type":"TXT","value":"rp=ipp/print;ty=Office Printer"}]},
        {"source":"10.0.0.4","records":[{"name":"printer.local","type":"A","value":"10.0.0.50"},{"name":"printer.local","type":"AAAA","value":"fe80::1234"}]},
    ]
    rows=build_service_chains(packets)
    assert len(rows)==1
    row=rows[0]
    assert row["port"]=="631"
    assert row["target"]=="printer.local"
    assert row["addresses"]==["10.0.0.50","fe80::1234"]
    assert row["status"]=="Complete chain"
    assert set(row["evidence"])=={"PTR","SRV","TXT","A/AAAA"}


def test_missing_target_is_not_called_complete():
    rows=build_service_chains([{"source":"10.0.0.2","records":[{"name":"_airplay._tcp.local","type":"PTR","value":"Living Room._airplay._tcp.local"}]}])
    assert rows[0]["status"]=="PTR only"
    assert not rows[0]["addresses"]


def test_deduplicates_identical_records_and_surfaces_srv_conflicts():
    packets=[
        {"timestamp":100,"source":"10.0.0.2","records":[{"name":"_ipp._tcp.local","type":"PTR","value":"Printer._ipp._tcp.local.","ttl":120}]},
        {"timestamp":101,"source":"10.0.0.2","records":[{"name":"Printer._ipp._tcp.local","type":"SRV","value":"port=631 target=p1.local","ttl":120}]},
        {"timestamp":102,"source":"10.0.0.3","records":[{"name":"Printer._ipp._tcp.local","type":"SRV","value":"port=9100 target=p2.local","ttl":120}]},
        {"timestamp":103,"source":"10.0.0.2","records":[{"name":"p1.local","type":"A","value":"10.0.0.9","ttl":120}]},
    ]
    row=build_service_chains(packets)[0]
    assert row["conflicts"]
    assert row["status"] == "Conflicting SRV records"


def test_ttl_zero_goodbye_removes_record_and_expired_record_is_ignored():
    goodbye=[
        {"timestamp":100,"source":"10.0.0.2","records":[{"name":"_ipp._tcp.local","type":"PTR","value":"Printer._ipp._tcp.local.","ttl":120}]},
        {"timestamp":101,"source":"10.0.0.2","records":[{"name":"_ipp._tcp.local","type":"PTR","value":"Printer._ipp._tcp.local.","ttl":0}]},
    ]
    assert build_service_chains(goodbye) == []
    expired=[
        {"timestamp":100,"source":"10.0.0.2","records":[{"name":"_ipp._tcp.local","type":"PTR","value":"Printer._ipp._tcp.local.","ttl":2}]},
        {"timestamp":105,"source":"10.0.0.2","records":[]},
    ]
    assert build_service_chains(expired) == []


def test_comparison_uses_service_instance_and_reports_mismatched_target():
    from service_correlation import compare_discoveries
    rows=compare_discoveries([{"instance":"Printer._ipp._tcp.local.","target":"old.local","port":"631","status":"Complete chain","conflicts":[]}],
        [{"fullname":"printer._ipp._tcp.local","host":"new.local","port":"631","status":"Resolved"}])
    assert len(rows)==1 and rows[0]["passive_seen"] and rows[0]["active_seen"]
    assert "target differs" in rows[0]["interpretation"]


def test_duplicate_observations_are_counted_without_duplicate_service_rows():
    packets=[
        {"timestamp":100,"source":"10.0.0.2","records":[{"name":"_ipp._tcp.local","type":"PTR","value":"Printer._ipp._tcp.local.","ttl":120}]},
        {"timestamp":101,"source":"10.0.0.2","records":[{"name":"_ipp._tcp.local","type":"PTR","value":"Printer._ipp._tcp.local.","ttl":120}]},
    ]
    rows=build_service_chains(packets)
    assert len(rows)==1
    assert rows[0]["record_counts"]["PTR"]==2
    assert rows[0]["duplicate_observations"]==1


def test_txt_payload_case_is_preserved():
    packets=[
        {"timestamp":100,"source":"10.0.0.2","records":[{"name":"_ipp._tcp.local","type":"PTR","value":"Printer._ipp._tcp.local.","ttl":120}]},
        {"timestamp":101,"source":"10.0.0.2","records":[
            {"name":"Printer._ipp._tcp.local","type":"TXT","value":"Model=ABC","ttl":120},
            {"name":"Printer._ipp._tcp.local","type":"TXT","value":"model=abc","ttl":120},
        ]},
    ]
    row=build_service_chains(packets)[0]
    assert set(row["txt"]) == {"Model=ABC", "model=abc"}
    assert row["record_counts"]["TXT"] == 2


def test_refreshing_record_resets_ttl_window():
    packets=[
        {"timestamp":100,"source":"10.0.0.2","records":[{"name":"_ipp._tcp.local","type":"PTR","value":"Printer._ipp._tcp.local.","ttl":3}]},
        {"timestamp":102,"source":"10.0.0.2","records":[{"name":"_ipp._tcp.local","type":"PTR","value":"Printer._ipp._tcp.local.","ttl":3}]},
        {"timestamp":104,"source":"10.0.0.2","records":[]},
    ]
    assert len(build_service_chains(packets)) == 1


def test_parses_srv_target_port_formats_from_packet_decoder():
    packets=[
        {"timestamp":100,"source":"10.0.0.2","records":[{"name":"_airplay._tcp.local","type":"PTR","value":"Den TV._airplay._tcp.local.","ttl":120}]},
        {"timestamp":101,"source":"10.0.0.2","records":[{"name":"Den TV._airplay._tcp.local","type":"SRV","value":"tv.local:7000","ttl":120}]},
        {"timestamp":102,"source":"10.0.0.3","records":[{"name":"tv.local","type":"A","value":"10.0.0.70","ttl":120}]},
    ]
    row=build_service_chains(packets)[0]
    assert row["target"]=="tv.local" and row["port"]=="7000"
    assert row["addresses"]==["10.0.0.70"]
    assert row["status"]=="Complete chain"


def test_parses_scapy_style_srv_repr():
    from service_correlation import _srv
    assert _srv("SRV(prio=0, weight=0, port=7000, target='tv.local.')")==("7000","tv.local")


def test_high_packet_count_without_dns_sd_records_does_not_create_fake_chains():
    packets=[{"timestamp":i,"source":"10.0.0.2","records":[{"name":"_services._dns-sd._udp.local","type":"PTR","value":"_services._dns-sd._udp.local"}]} for i in range(1200)]
    # Meta-discovery records are not service-instance advertisements.
    assert build_service_chains(packets)==[]

if __name__=="__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn): fn()
    print("PASS: service correlation tests")
