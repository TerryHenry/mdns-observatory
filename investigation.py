"""Evidence-oriented investigation summaries for mDNS Observatory."""
from collections import Counter, defaultdict
from datetime import datetime


def _stamp(packet):
    value = packet.get('timestamp')
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(packet.get('time', '')).replace('Z', '+00:00')).timestamp()
    except (ValueError, TypeError, OverflowError):
        return None


def build_timeline(packets, bucket_seconds=60):
    """Return capture-relative timeline buckets, ignoring unparseable timestamps."""
    buckets = defaultdict(lambda: {'packets': 0, 'queries': 0, 'responses': 0, 'sources': set()})
    stamps = [_stamp(p) for p in packets or []]
    valid = [x for x in stamps if x is not None]
    if not valid:
        return []
    origin = min(valid)
    for packet, ts in zip(packets or [], stamps):
        if ts is None:
            continue
        index = int((ts - origin) // max(1, int(bucket_seconds)))
        row = buckets[index]
        row['packets'] += 1
        row['queries'] += int(packet.get('direction') == 'Query')
        row['responses'] += int(packet.get('direction') == 'Response')
        if packet.get('source'):
            row['sources'].add(str(packet['source']))
    return [{'offset_seconds': i * bucket_seconds, 'packets': v['packets'], 'queries': v['queries'],
             'responses': v['responses'], 'sources': len(v['sources'])} for i, v in sorted(buckets.items())]


def correlate_queries_responses(packets, window_seconds=5):
    """Conservative evidence correlation by question/record name and nearby time.

    It reports candidate links, not authoritative DNS transaction matching: mDNS IDs are
    often zero and PTR answers may reference instances rather than repeat the queried name.
    """
    queries, responses = [], []
    for idx, packet in enumerate(packets or []):
        ts = _stamp(packet)
        if packet.get('direction') == 'Query':
            for question in packet.get('questions', []) or []:
                queries.append((idx, ts, packet, str(question.get('name', '')).rstrip('.').casefold(), str(question.get('type', '')).upper()))
        elif packet.get('direction') == 'Response':
            for record in packet.get('records', []) or []:
                responses.append((idx, ts, packet, str(record.get('name', '')).rstrip('.').casefold(), str(record.get('type', '')).upper()))
    output = []
    for qidx, qts, qp, qname, qtype in queries:
        if not qname:
            continue
        matches = []
        for ridx, rts, rp, rname, rtype in responses:
            if rname != qname or (qtype not in ('', 'ANY') and rtype != qtype):
                continue
            if qts is not None and rts is not None and (rts < qts or rts - qts > window_seconds):
                continue
            # Prefer response traffic to the querying host or mDNS multicast group.
            if qp.get('source') and rp.get('destination') not in (qp.get('source'), '224.0.0.251', 'ff02::fb'):
                continue
            matches.append((ridx, rp))
        if matches:
            ridx, rp = matches[0]
            output.append({'query_index': qidx, 'response_index': ridx, 'name': qname, 'type': qtype,
                           'source': qp.get('source', ''), 'responder': rp.get('source', ''),
                           'delta_seconds': round(max(0, (_stamp(rp) or 0) - (qts or 0)), 3),
                           'confidence': 'Candidate match', 'evidence': 'Same question/record name and type within time window'})
    return output


def build_prioritized_findings(packets, chains, devices):
    findings = []
    for chain in chains or []:
        conflicts = chain.get('conflicts') or []
        if conflicts:
            findings.append({'priority': 'High', 'finding': 'Conflicting service records',
                             'subject': chain.get('instance', ''), 'evidence': '; '.join(map(str, conflicts)),
                             'action': 'Inspect the service chain and supporting packets.'})
        if not chain.get('target') or not chain.get('addresses'):
            findings.append({'priority': 'Medium', 'finding': 'Incomplete service chain',
                             'subject': chain.get('instance', ''),
                             'evidence': f"target={chain.get('target') or 'not observed'}; addresses={', '.join(chain.get('addresses') or []) or 'not observed'}",
                             'action': 'Check capture scope and PTR/SRV/A/AAAA record evidence.'})
    for device in devices or []:
        q, r = int(device.get('queries', 0) or 0), int(device.get('responses', 0) or 0)
        if q >= 10 and q >= max(1, r) * 4:
            findings.append({'priority': 'Medium', 'finding': 'Query-heavy source', 'subject': device.get('ip', ''),
                             'evidence': f'{q} queries versus {r} responses observed for this source',
                             'action': 'Inspect source packet timeline and repeated question names.'})
    if not packets:
        findings.append({'priority': 'Info', 'finding': 'No retained packet evidence', 'subject': 'Capture',
                         'evidence': 'The current session has no retained decoded mDNS packets.',
                         'action': 'Import a capture or start capture on the intended interface.'})
    rank = {'High': 0, 'Medium': 1, 'Low': 2, 'Info': 3}
    return sorted(findings, key=lambda x: (rank.get(x['priority'], 9), x['subject'], x['finding']))


def build_investigation(packets, chains, devices):
    return {'timeline': build_timeline(packets),
            'query_response_candidates': correlate_queries_responses(packets),
            'findings': build_prioritized_findings(packets, chains, devices),
            'evidence_scope': 'Analysis uses retained decoded packet history. Candidate correlations are heuristic, not proof of causality.'}
