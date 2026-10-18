"""Evidence-backed comparison of two retained mDNS packet captures."""
from collections import Counter, defaultdict


def _canon_record(r):
    return (str(r.get('name','')).rstrip('.').lower(), str(r.get('type','')).upper(), str(r.get('value','')).strip().lower())


def summarize_capture(packets, label='capture'):
    records=defaultdict(list); devices=defaultdict(list); traffic=Counter(); services=defaultdict(list)
    for i,p in enumerate(packets):
        src=str(p.get('source','')); mac=str(p.get('mac','')); direction=str(p.get('direction','Unknown'))
        traffic['packets']+=1; traffic[direction.lower()]+=1
        if src:
            devices[(src,mac)].append((i,p))
        for r in p.get('records',[]) or []:
            key=_canon_record(r)
            records[key].append((i,p,r))
            name=key[0]
            if key[1]=='PTR' and ('._tcp.local' in name or '._udp.local' in name):
                services[(name,key[2])].append((i,p,r))
    return {'label':label,'packets':list(packets),'records':records,'devices':devices,'services':services,'traffic':traffic}


def compare_captures(baseline_packets, current_packets, baseline_label='Baseline', current_label='Current'):
    """Return differences with direct packet-index and packet-summary evidence."""
    a=summarize_capture(baseline_packets,baseline_label); b=summarize_capture(current_packets,current_label)
    out=[]
    def evidence(side, entries):
        if not entries: return 'No retained matching packet evidence.'
        bits=[]
        for idx,p,*_ in entries[:3]:
            bits.append(f"{side} packet #{idx+1}: {p.get('time','')} {p.get('source','?')} → {p.get('destination','?')} ({p.get('direction','?')})")
        if len(entries)>3: bits.append(f"+{len(entries)-3} more matching packets")
        return '; '.join(bits)
    for key in sorted(set(a['records'])|set(b['records'])):
        old=a['records'].get(key,[]); new=b['records'].get(key,[])
        if bool(old)==bool(new):
            continue
        typ='DNS-SD service advertisement' if key[1]=='PTR' and ('._tcp.local' in key[0] or '._udp.local' in key[0]) else 'DNS-SD record'
        out.append({'category':'Service' if typ.startswith('DNS-SD service') else 'Record','change':'Removed from current' if old else 'New in current','subject':f'{key[0]} [{key[1]}] → {key[2]}','baseline_count':len(old),'current_count':len(new),'evidence':f"{baseline_label}: {evidence('baseline',old)} | {current_label}: {evidence('current',new)}",'baseline_evidence':old,'current_evidence':new})
    # Device comparison uses source IP/MAC identity; presence means observed as a packet source.
    old_by_ip=defaultdict(list); new_by_ip=defaultdict(list)
    for (ip,mac),entries in a['devices'].items(): old_by_ip[ip].append((mac,entries))
    for (ip,mac),entries in b['devices'].items(): new_by_ip[ip].append((mac,entries))
    for ip in sorted(set(old_by_ip)|set(new_by_ip)):
        old=old_by_ip.get(ip,[]); new=new_by_ip.get(ip,[])
        oldmac={x[0] for x in old}; newmac={x[0] for x in new}
        if not old: change='New responding source'
        elif not new: change='Not observed in current'
        elif oldmac != newmac: change='MAC identity changed'
        else: continue
        oldentries=[e for _,es in old for e in es]; newentries=[e for _,es in new for e in es]
        oldmac_text=', '.join(sorted(oldmac or {'—'})); newmac_text=', '.join(sorted(newmac or {'—'}))
        out.append({'category':'Device','change':change,'subject':f'{ip} (MAC: {oldmac_text} → {newmac_text})','baseline_count':len(oldentries),'current_count':len(newentries),'evidence':f"{baseline_label}: {evidence('baseline',oldentries)} | {current_label}: {evidence('current',newentries)}",'baseline_evidence':oldentries,'current_evidence':newentries})
    # Traffic differences are aggregate observations, not proof of service health.
    for metric in ('packets','query','response'):
        av=a['traffic'].get(metric,0); bv=b['traffic'].get(metric,0)
        if av!=bv:
            out.append({'category':'Traffic','change':'Increased' if bv>av else 'Decreased','subject':('Packet count' if metric=='packets' else f'{metric.title()} count'),'baseline_count':av,'current_count':bv,'evidence':f"{baseline_label}: {av} retained decoded mDNS packets; {current_label}: {bv} retained decoded mDNS packets. Capture windows and interfaces should be comparable before interpreting this as a network change.",'baseline_evidence':[],'current_evidence':[]})
    return {'baseline':{'label':baseline_label,'packet_count':len(baseline_packets),'record_count':sum(len(v) for v in a['records'].values()),'device_count':len({ip for ip,_ in a['devices']})},'current':{'label':current_label,'packet_count':len(current_packets),'record_count':sum(len(v) for v in b['records'].values()),'device_count':len({ip for ip,_ in b['devices']})},'differences':out,'notes':['Comparison uses retained decoded mDNS packets only.','Not observed does not prove unavailable; capture duration, interface, VLAN visibility, and packet loss can explain differences.','Traffic count comparisons are meaningful only when capture windows and observation points are reasonably comparable.']}
