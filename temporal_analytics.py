"""Time-windowed mDNS discovery analytics with conservative evidence semantics."""
from collections import Counter, defaultdict
from datetime import datetime


def _parse_time(value):
    try:
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value or '').strip()
        if not text:
            return None
        try:
            return datetime.fromisoformat(text.replace('Z', '+00:00')).timestamp()
        except ValueError:
            return float(text)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _direction(packet):
    return str(packet.get('direction', '')).strip().lower()


def _questions(packet):
    result = []
    raw = packet.get('questions', []) or []
    if isinstance(raw, str):
        raw = [{'name': raw, 'type': 'ANY'}]
    for q in raw:
        if isinstance(q, dict):
            name = str(q.get('name', '')).strip().lower().rstrip('.')
            typ = str(q.get('type', 'ANY')).upper()
        else:
            name, typ = str(q).strip().lower().rstrip('.'), 'ANY'
        if name:
            result.append((name, typ))
    return result


def _records(packet):
    out = []
    for rr in packet.get('records', []) or []:
        if isinstance(rr, dict):
            name = str(rr.get('name', '')).strip().lower().rstrip('.')
            typ = str(rr.get('type', '')).upper()
            value = str(rr.get('value', rr.get('target', ''))).strip().lower().rstrip('.')
            if name:
                out.append((name, typ, value))
    return out


def analyze_temporal_discovery(packets, window_seconds=60, response_window_seconds=5):
    """Summarize likely query outcomes and recurrence by time window.

    A response is a *candidate correlated response*, not proof of delivery or
    application success. Queries with no candidate are classified as unanswered
    in the retained capture only. Persistent means observed in multiple windows.
    """
    packets = list(packets or [])
    window_seconds = max(10, int(window_seconds))
    normalized = []
    for i, p in enumerate(packets):
        ts = _parse_time(p.get('time'))
        if ts is not None:
            normalized.append({'index': i, 'ts': ts, 'packet': p})
    normalized.sort(key=lambda x: (x['ts'], x['index']))
    if not normalized:
        return {'available': False, 'reason': 'No parseable packet timestamps are available.',
                'window_seconds': window_seconds, 'windows': [], 'queries': [], 'patterns': [],
                'summary': {'queries': 0, 'candidate_answered': 0, 'no_candidate': 0}}

    start = normalized[0]['ts']
    windows = defaultdict(lambda: {'packets': [], 'queries': 0, 'responses': 0, 'sources': set()})
    queries = []
    responses = []
    for item in normalized:
        p = item['packet']
        wi = int((item['ts'] - start) // window_seconds)
        w = windows[wi]
        w['packets'].append(item['index'])
        w['sources'].add(str(p.get('source') or 'unknown'))
        d = _direction(p)
        if d == 'query':
            w['queries'] += 1
            for name, typ in _questions(p):
                queries.append({**item, 'window': wi, 'name': name, 'type': typ, 'source': str(p.get('source') or 'unknown')})
        elif d == 'response':
            w['responses'] += 1
            responses.append({**item, 'window': wi, 'records': _records(p), 'source': str(p.get('source') or 'unknown')})

    response_hits = defaultdict(list)
    for q in queries:
        for r in responses:
            delta = r['ts'] - q['ts']
            if delta < 0 or delta > response_window_seconds:
                continue
            # Exact owner-name match is strongest. PTR service-type questions
            # can be answered by a PTR record with that owner; avoid broad guesses.
            matching = [rr for rr in r['records'] if rr[0] == q['name'] and (q['type'] in ('ANY', rr[1]) or rr[1] == 'ANY')]
            if matching:
                response_hits[q['index']].append({'index': r['index'], 'source': r['source'], 'delta': round(delta, 3), 'record_types': sorted({rr[1] for rr in matching})})

    query_rows = []
    pattern_windows = defaultdict(lambda: {'windows': set(), 'queries': 0, 'answered': 0, 'unanswered': 0, 'query_indices': [], 'response_indices': []})
    for q in queries:
        hits = response_hits.get(q['index'], [])
        row = {'query_index': q['index'], 'time': q['packet'].get('time', ''), 'window': q['window'],
               'name': q['name'], 'type': q['type'], 'source': q['source'],
               'status': 'Candidate response observed' if hits else 'No matching response observed',
               'response_candidates': hits, 'evidence_indices': [q['index']] + [h['index'] for h in hits]}
        query_rows.append(row)
        sig = (q['name'], q['type'], q['source'])
        agg = pattern_windows[sig]
        agg['windows'].add(q['window']); agg['queries'] += 1
        agg['answered' if hits else 'unanswered'] += 1
        agg['query_indices'].append(q['index'])
        agg['response_indices'].extend(h['index'] for h in hits)

    patterns = []
    for (name, typ, source), agg in pattern_windows.items():
        count_windows = len(agg['windows'])
        unanswered_ratio = agg['unanswered'] / agg['queries'] if agg['queries'] else 0
        if count_windows >= 2 and unanswered_ratio >= 0.5:
            classification = 'Recurring concern'
            interpretation = 'Repeated in multiple time windows; worth investigating as a persistent pattern.'
        elif count_windows >= 2:
            classification = 'Recurring activity'
            interpretation = 'Repeated across windows, with candidate responses also observed.'
        elif agg['queries'] >= 2 and unanswered_ratio >= 0.5:
            classification = 'Single-window burst'
            interpretation = 'Repeated within one window only; not enough evidence to call it persistent.'
        elif agg['unanswered']:
            classification = 'One-off / unconfirmed'
            interpretation = 'No matching response was observed for this query in the retained capture.'
        else:
            classification = 'Candidate response observed'
            interpretation = 'A related response record was observed soon after the query; delivery and application success are not proven.'
        patterns.append({'name': name, 'type': typ, 'source': source, 'query_count': agg['queries'],
                         'candidate_answered': agg['answered'], 'no_candidate': agg['unanswered'],
                         'windows_seen': count_windows, 'classification': classification,
                         'interpretation': interpretation,
                         'evidence_indices': sorted(set(agg['query_indices'] + agg['response_indices']))})
    patterns.sort(key=lambda x: (x['classification'] not in ('Recurring concern', 'Single-window burst'), -x['no_candidate'], -x['query_count']))
    window_rows = []
    for wi in sorted(windows):
        w = windows[wi]
        window_rows.append({'window': wi, 'offset_start_s': wi * window_seconds,
                            'offset_end_s': (wi + 1) * window_seconds,
                            'packets': len(w['packets']), 'queries': w['queries'], 'responses': w['responses'],
                            'distinct_sources': len(w['sources']), 'packet_indices': w['packets']})
    answered = sum(1 for q in query_rows if q['response_candidates'])
    return {'available': True, 'reason': '', 'window_seconds': window_seconds, 'windows': window_rows,
            'queries': query_rows, 'patterns': patterns,
            'summary': {'queries': len(query_rows), 'candidate_answered': answered,
                        'no_candidate': len(query_rows) - answered,
                        'distinct_query_patterns': len(patterns), 'time_windows': len(window_rows)},
            'caveat': 'Candidate response correlation uses exact question-name/record-owner matching and a short time window. It does not prove multicast delivery, that every query was answered, or that an application worked.'}
