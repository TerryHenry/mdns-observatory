"""Dependency-free PCAP/PCAPNG and mDNS decoder for mDNS Observatory."""
from __future__ import annotations
import ipaddress, socket, struct
from datetime import datetime, timezone

DLT_EN10MB = 1
DLT_RAW = 101
DLT_RAW_BSD = 12
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276
MAX_CAPTURE_BLOCK_BYTES = 64 * 1024 * 1024


def read_capture(path):
    """Yield (timestamp_seconds, linktype, frame_bytes) from classic PCAP or PCAPNG."""
    with open(path, 'rb') as f:
        magic=f.read(4); f.seek(0)
        if magic == b'\x0a\x0d\x0d\x0a':
            yield from _read_pcapng(f); return
        yield from _read_pcap(f)


def _read_pcap(f):
    h=f.read(24)
    if len(h)<24: raise ValueError('Capture file is too short to contain a PCAP header')
    magic=h[:4]
    formats={b'\xd4\xc3\xb2\xa1':('<',1e-6),b'\xa1\xb2\xc3\xd4':('>',1e-6),b'\x4d\x3c\xb2\xa1':('<',1e-9),b'\xa1\xb2\x3c\x4d':('>',1e-9)}
    if magic not in formats: raise ValueError('Unrecognized PCAP byte order or format')
    endian,scale=formats[magic]
    _major,_minor,_zone,_sigfigs,snaplen,linktype=struct.unpack(endian+'HHIIII',h[4:24])
    if snaplen > MAX_CAPTURE_BLOCK_BYTES:
        raise ValueError('PCAP snap length exceeds the 64 MiB safety limit')
    while True:
        ph=f.read(16)
        if not ph: break
        if len(ph)<16: raise ValueError('Truncated PCAP packet header')
        sec,frac,caplen,origlen=struct.unpack(endian+'IIII',ph)
        if caplen > MAX_CAPTURE_BLOCK_BYTES:
            raise ValueError('PCAP captured packet exceeds the 64 MiB safety limit')
        if caplen > origlen:
            raise ValueError('PCAP captured packet length exceeds original packet length')
        if snaplen and caplen > snaplen:
            raise ValueError('PCAP captured packet length exceeds interface snap length')
        frame=f.read(caplen)
        if len(frame)!=caplen: raise ValueError('Truncated PCAP frame')
        yield sec+frac*scale,linktype,frame


def _read_pcapng(f):
    endian=None; interfaces=[]
    while True:
        start=f.read(8)
        if not start: break
        if len(start)<8: raise ValueError('Truncated PCAPNG block header')
        typ_raw=start[:4]
        if typ_raw==b'\x0a\x0d\x0d\x0a':
            bom=f.read(4)
            if len(bom)!=4: raise ValueError('Truncated PCAPNG byte-order magic')
            if bom==b'\x4d\x3c\x2b\x1a': endian='<'
            elif bom==b'\x1a\x2b\x3c\x4d': endian='>'
            else: raise ValueError('Invalid PCAPNG byte-order magic')
            total=struct.unpack(endian+'I',start[4:8])[0]
            if total<28: raise ValueError('Invalid PCAPNG section length')
            if total > MAX_CAPTURE_BLOCK_BYTES:
                raise ValueError('PCAPNG section header exceeds the 64 MiB safety limit')
            rest=f.read(total-12)
            if len(rest)!=total-12: raise ValueError('Truncated PCAPNG section header')
            if struct.unpack(endian+'I',rest[-4:])[0] != total:
                raise ValueError('PCAPNG section header length trailer mismatch')
            interfaces=[]
            continue
        if endian is None: raise ValueError('PCAPNG section header missing')
        typ,total=struct.unpack(endian+'II',start)
        if total<12: raise ValueError('Invalid PCAPNG block length')
        if total > MAX_CAPTURE_BLOCK_BYTES:
            raise ValueError('PCAPNG block exceeds the 64 MiB safety limit')
        body=f.read(total-8)
        if len(body)!=total-8: raise ValueError('Truncated PCAPNG block')
        if struct.unpack(endian+'I',body[-4:])[0]!=total: raise ValueError('PCAPNG block length trailer mismatch')
        data=body[:-4]
        if typ==1: # Interface Description Block
            if len(data)<8: continue
            linktype,reserved,snaplen=struct.unpack(endian+'HHI',data[:8]); ts_num=1_000_000
            pos=8
            while pos+4<=len(data):
                code,length=struct.unpack(endian+'HH',data[pos:pos+4]); pos+=4
                if code==0: break
                opt=data[pos:pos+length]
                if code==9 and opt:
                    # if_tsresol: high bit means base 2, otherwise base 10
                    b=opt[0]; ts_num=(2**(b&0x7f) if b&0x80 else 10**b)
                pos+=(length+3)&~3
            interfaces.append((linktype,ts_num))
        elif typ==6: # Enhanced Packet Block
            if len(data)<20: continue
            iid,hi,lo,caplen,origlen=struct.unpack(endian+'IIIII',data[:20])
            if iid>=len(interfaces): continue
            available = len(data) - 20
            if caplen > available:
                raise ValueError('PCAPNG enhanced packet block has truncated frame data')
            if caplen > origlen:
                raise ValueError('PCAPNG captured frame length exceeds original frame length')
            frame=data[20:20+caplen]
            linktype,ts_num=interfaces[iid]
            yield ((hi<<32)|lo)/ts_num,linktype,frame
        elif typ==2: # obsolete Packet Block
            if len(data)<20: continue
            iid,hi,lo,caplen,origlen=struct.unpack(endian+'HHIIII',data[:16])
            if iid>=len(interfaces): continue
            available = len(data) - 16
            if caplen > available:
                raise ValueError('PCAPNG packet block has truncated frame data')
            if caplen > origlen:
                raise ValueError('PCAPNG captured frame length exceeds original frame length')
            linktype,ts_num=interfaces[iid]
            yield ((hi<<32)|lo)/ts_num,linktype,data[16:16+caplen]
        elif typ==3: # Simple Packet Block, no timestamp
            if data and interfaces:
                if len(data) < 4:
                    raise ValueError('PCAPNG simple packet block is missing original length')
                origlen=struct.unpack(endian+'I',data[:4])[0]
                captured = min(origlen, len(data) - 4)
                # Packet data is padded to a 32-bit boundary; the original length
                # may exceed captured length when the interface snaplen truncated it.
                frame=data[4:4+captured]
                yield 0.0,interfaces[0][0],frame


def _dns_name(buf, offset):
    labels=[]; pos=offset; end=None; jumps=0
    while True:
        if pos>=len(buf): raise ValueError('DNS name exceeds packet bounds')
        n=buf[pos]
        if n==0:
            pos+=1
            if end is None: end=pos
            break
        if n&0xc0==0xc0:
            if pos+1>=len(buf): raise ValueError('Truncated DNS compression pointer')
            ptr=((n&0x3f)<<8)|buf[pos+1]
            if end is None: end=pos+2
            pos=ptr; jumps+=1
            if jumps>32: raise ValueError('DNS compression pointer loop')
            continue
        if n&0xc0: raise ValueError('Unsupported DNS label encoding')
        pos+=1
        if pos+n>len(buf): raise ValueError('Truncated DNS label')
        labels.append(buf[pos:pos+n].decode('utf-8','replace')); pos+=n
        if len(labels)>127: raise ValueError('DNS name has too many labels')
    return '.'.join(labels),end


def _parse_dns(buf):
    if len(buf)<12: raise ValueError('DNS header is truncated')
    ident,flags,qd,an,ns,ar=struct.unpack('!HHHHHH',buf[:12]); pos=12
    questions=[]; records=[]
    for _ in range(qd):
        name,pos=_dns_name(buf,pos)
        if pos+4>len(buf): raise ValueError('Truncated DNS question')
        typ,cls=struct.unpack('!HH',buf[pos:pos+4]); pos+=4
        questions.append({'name':name,'type':_qtype(typ)})
    for section,count in (('answer',an),('authority',ns),('additional',ar)):
        for _ in range(count):
            name,pos=_dns_name(buf,pos)
            if pos+10>len(buf): raise ValueError('Truncated DNS resource record header')
            typ,cls,ttl,rdlen=struct.unpack('!HHIH',buf[pos:pos+10]); pos+=10; rstart=pos; rend=pos+rdlen
            if rend>len(buf): raise ValueError('Truncated DNS resource record data')
            value=''
            if typ==1 and rdlen==4: value=str(ipaddress.IPv4Address(buf[rstart:rend]))
            elif typ==28 and rdlen==16: value=str(ipaddress.IPv6Address(buf[rstart:rend]))
            elif typ in (2,5,12,39): value=_dns_name(buf,rstart)[0]
            elif typ==33 and rdlen>=6:
                priority,weight,port=struct.unpack('!HHH',buf[rstart:rstart+6]); target=_dns_name(buf,rstart+6)[0]
                value=f'priority={priority} weight={weight} port={port} target={target}'
            elif typ==16:
                chunks=[]; p=rstart
                while p<rend:
                    n=buf[p]; p+=1
                    if p+n>rend: break
                    chunks.append(buf[p:p+n].decode('utf-8','replace')); p+=n
                value='; '.join(chunks)
            elif typ==41: value='EDNS OPT'
            else: value=buf[rstart:rend].hex() if rdlen else ''
            records.append({'section':section,'name':name,'type':_qtype(typ),'ttl':ttl,'value':value})
            pos=rend
    return {'id':ident,'qr':(flags>>15)&1,'questions':questions,'records':records,'counts':(qd,an,ns,ar)}


def _qtype(t): return {1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',16:'TXT',28:'AAAA',33:'SRV',41:'OPT',47:'NSEC',255:'ANY'}.get(t,f'TYPE{t}')



def _unwrap_erspan(frame, linktype):
    """Return (inner Ethernet frame, metadata) for recognized ERSPAN II/III.

    Capture backends can expose the outer IPv4 packet either with Ethernet
    framing (DLT_EN10MB) or as raw IP (DLT_RAW / DLT_RAW_BSD). Accept both.
    """
    if linktype == DLT_EN10MB:
        if len(frame) < 14:
            return None
        pos = 14
        etype = struct.unpack('!H', frame[12:14])[0]
        while etype in (0x8100, 0x88a8, 0x9100):
            if len(frame) < pos + 4:
                return None
            etype = struct.unpack('!H', frame[pos+2:pos+4])[0]
            pos += 4
        if etype != 0x0800:
            return None
    elif linktype in (DLT_RAW, DLT_RAW_BSD):
        pos = 0
        if not frame or (frame[0] >> 4) != 4:
            return None
    else:
        return None
    if len(frame) < pos + 20:
        return None
    if (frame[pos] >> 4) != 4:
        return None
    ihl = (frame[pos] & 0x0f) * 4
    if ihl < 20 or len(frame) < pos + ihl or frame[pos+9] != 47:
        return None
    total_len = struct.unpack('!H', frame[pos+2:pos+4])[0]
    ip_end = min(len(frame), pos + total_len) if total_len >= ihl else len(frame)
    # Fragmented outer GRE cannot be decoded reliably from a single frame.
    frag = struct.unpack('!H', frame[pos+6:pos+8])[0]
    if frag & 0x3fff:
        return None
    outer_src = socket.inet_ntop(socket.AF_INET, frame[pos+12:pos+16])
    outer_dst = socket.inet_ntop(socket.AF_INET, frame[pos+16:pos+20])
    gre = pos + ihl
    if ip_end < gre + 4:
        return None
    flags, proto = struct.unpack('!HH', frame[gre:gre+4])
    if proto not in (0x88be, 0x22eb):
        return None
    # GRE optional checksum/routing, key and sequence fields, in RFC order.
    cursor = gre + 4
    if flags & 0x8000 or flags & 0x4000:
        cursor += 4
    if flags & 0x2000:
        cursor += 4
    if flags & 0x1000:
        cursor += 4
    if cursor > ip_end:
        return None
    header_len = 8 if proto == 0x88be else 12
    if ip_end < cursor + header_len + 14:
        return None
    inner = frame[cursor+header_len:ip_end]
    if len(inner) < 14:
        return None
    return inner, {'outer_source': outer_src, 'outer_destination': outer_dst,
                   'erspan_type': 'II' if proto == 0x88be else 'III', 'gre_protocol': proto}

def decode_frame(frame, linktype, ts=0.0):
    """Decode Ethernet/RAW/Linux cooked frame, including mDNS inside ERSPAN II/III."""
    tunnel = _unwrap_erspan(frame, linktype)
    if tunnel:
        inner, metadata = tunnel
        info = decode_frame(inner, DLT_EN10MB, ts)
        if info:
            info['source_type'] = 'erspan'
            info['capture_method'] = 'pcap'
            info['capture_origin'] = 'erspan'
            info['tunnel'] = metadata
            info['bytes'] = len(frame)
        return info
    pos=0; srcmac=''; vlan='Unknown / not tagged'; ethertype=None
    if linktype==DLT_EN10MB:
        if len(frame)<14: return None
        srcmac=':'.join(f'{x:02x}' for x in frame[6:12]); ethertype=struct.unpack('!H',frame[12:14])[0]; pos=14
        while ethertype in (0x8100,0x88a8,0x9100):
            if len(frame)<pos+4: return None
            tci,ethertype=struct.unpack('!HH',frame[pos:pos+4]); vlan=str(tci&0x0fff); pos+=4
    elif linktype in (DLT_RAW,DLT_RAW_BSD):
        if not frame: return None
        version=frame[0]>>4; ethertype=0x0800 if version==4 else 0x86dd if version==6 else 0
    elif linktype==DLT_LINUX_SLL:
        if len(frame)<16:return None
        ethertype=struct.unpack('!H',frame[14:16])[0]; srcmac=':'.join(f'{x:02x}' for x in frame[6:12]); pos=16
    elif linktype==DLT_LINUX_SLL2:
        if len(frame)<20:return None
        ethertype=struct.unpack('!H',frame[:2])[0]; srcmac=':'.join(f'{x:02x}' for x in frame[12:18]); pos=20
    else: return None
    src=dst=''; family='unknown'; proto=None; payload=b''
    if ethertype==0x0800:
        if len(frame)<pos+20:return None
        ihl=(frame[pos]&15)*4
        if ihl<20 or len(frame)<pos+ihl:return None
        if frame[pos+9]!=17:return None
        src=socket.inet_ntop(socket.AF_INET,frame[pos+12:pos+16]); dst=socket.inet_ntop(socket.AF_INET,frame[pos+16:pos+20]); family='IPv4'; p=pos+ihl
        if len(frame)<p+8:return None
        sport,dport,ulen=struct.unpack('!HHH',frame[p:p+6]); payload=frame[p+8:min(p+ulen,len(frame))]
    elif ethertype==0x86dd:
        if len(frame)<pos+40:return None
        src=socket.inet_ntop(socket.AF_INET6,frame[pos+8:pos+24]); dst=socket.inet_ntop(socket.AF_INET6,frame[pos+24:pos+40]); family='IPv6'; next_header=frame[pos+6]; plen=struct.unpack('!H',frame[pos+4:pos+6])[0]; p=pos+40; end=min(len(frame),p+plen)
        # Skip common IPv6 extension headers safely.
        while next_header in (0,43,60,44,51):
            if next_header==44:
                if p+8>end:return None
                next_header=frame[p]; size=8
            elif next_header==51:
                if p+2>end:return None
                size=(frame[p+1]+2)*4; next_header=frame[p]
            else:
                if p+2>end:return None
                size=(frame[p+1]+1)*8; next_header=frame[p]
            p+=size
            if p>end:return None
        if next_header!=17 or p+8>end:return None
        sport,dport,ulen=struct.unpack('!HHH',frame[p:p+6]); payload=frame[p+8:min(p+ulen,end)]
    else: return None
    if sport!=5353 and dport!=5353:return None
    dns=_parse_dns(payload)
    if not dns['questions'] and not dns['records']: return None
    stamp=datetime.fromtimestamp(ts).astimezone().isoformat(timespec='milliseconds') if ts else ''
    services=sorted({r['name'] for r in dns['records'] if '._tcp.local' in r['name'] or '._udp.local' in r['name']})
    return {'time':stamp,'timestamp':ts,'source':src,'destination':dst,'mac':srcmac,'vlan':vlan,'family':family,'sport':sport,'dport':dport,'direction':'Response' if dns['qr'] else 'Query','id':dns['id'],'questions':dns['questions'],'records':dns['records'],'rr_types':sorted({q['type'] for q in dns['questions']}|{r['type'] for r in dns['records']}),'services':services,'source_type':'local','capture_origin':'local','capture_method':'pcap','bytes':len(frame)}
