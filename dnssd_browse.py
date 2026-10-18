"""Native macOS Bonjour/DNS-SD browse and resolve worker using libdns_sd.

This uses Apple's system DNS-SD daemon; it does not raw-inject packets.
"""
from __future__ import annotations
import ctypes, ctypes.util, select, socket, threading, time, subprocess, re, shutil, os
from datetime import datetime

DEFAULT_TYPES = [
    "_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_ipp._tcp",
    "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_http._tcp",
    "_https._tcp", "_ssh._tcp", "_sftp-ssh._tcp", "_smb._tcp",
    "_afpovertcp._tcp", "_device-info._tcp", "_workstation._tcp",
    "_hap._tcp", "_homekit._tcp", "_companion-link._tcp", "_sleep-proxy._udp",
    "_services._dns-sd._udp",
]

BROWSE_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                             ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
                             ctypes.c_char_p, ctypes.c_void_p)
RESOLVE_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                              ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.c_uint16, ctypes.c_uint16, ctypes.POINTER(ctypes.c_ubyte),
                              ctypes.c_void_p)

class BonjourBrowser:
    """Run DNSServiceBrowse for multiple service types and resolve each result."""
    def __init__(self, on_event, on_status=None, interface_index=0):
        self.on_event = on_event
        self.on_status = on_status or (lambda _s: None)
        self.interface_index = int(interface_index or 0)
        self.stop_event = threading.Event()
        self.thread = None
        self.lib = None
        self.refs = []
        self.browse_refs = {}
        self.resolve_refs = {}
        self.callbacks = []
        self.lock = threading.RLock()
        self.errors = []
        self.discovered_types = set()
        self.cli_processes = []
        self.cli_threads = []
        self.backend = ""

    @staticmethod
    def _text(value):
        return value.decode('utf-8', 'replace') if value else ''

    def start(self, service_types=None):
        if self.thread and self.thread.is_alive():
            return
        types = service_types or DEFAULT_TYPES
        types = list(dict.fromkeys(t.strip().rstrip('.') for t in types if t.strip()))
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, args=(types,), daemon=True)
        self.thread.start()

    def stop(self):
        """Request shutdown and reap native dns-sd child processes promptly."""
        self.stop_event.set()
        processes = list(self.cli_processes)
        for proc in processes:
            try:
                if proc.poll() is None:
                    proc.terminate()
            except Exception:
                pass
        # Avoid leaving resolver children behind if a subprocess ignores SIGTERM.
        for proc in processes:
            try:
                if proc.poll() is None:
                    proc.wait(timeout=0.8)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=0.8)
                except Exception:
                    pass
        if self.thread and self.thread.is_alive() and self.thread is not threading.current_thread():
            self.thread.join(timeout=3.0)

    def _emit(self, item):
        try: self.on_event(item)
        except Exception: pass

    def _status(self, message):
        try: self.on_status(message)
        except Exception: pass

    def _run(self, types):
        try:
            if not hasattr(__import__('sys'), 'platform') or __import__('sys').platform != 'darwin':
                raise RuntimeError('Native Bonjour browsing is available in this build on macOS only.')
            libpath = ctypes.util.find_library('dns_sd') or '/usr/lib/libdns_sd.dylib'
            try:
                self.lib = ctypes.CDLL(libpath)
            except OSError as load_error:
                # Some macOS installations do not expose libdns_sd.dylib at the
                # traditional path. Use Apple's bundled dns-sd diagnostic client
                # as a native Bonjour fallback instead of leaving discovery empty.
                dns_sd = shutil.which('dns-sd')
                if not dns_sd:
                    raise RuntimeError(
                        f"Could not load Apple's DNS-SD library ({load_error}) and "
                        "the dns-sd command was not found. Check that this is a full macOS installation."
                    ) from load_error
                self.backend = 'dns-sd command fallback'
                self._run_cli(dns_sd, types)
                return
            self.backend = 'libdns_sd'
            self.lib.DNSServiceBrowse.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_char_p, BROWSE_CB, ctypes.c_void_p]
            self.lib.DNSServiceBrowse.restype = ctypes.c_int
            self.lib.DNSServiceResolve.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, RESOLVE_CB, ctypes.c_void_p]
            self.lib.DNSServiceResolve.restype = ctypes.c_int
            self.lib.DNSServiceRefSockFD.argtypes = [ctypes.c_void_p]; self.lib.DNSServiceRefSockFD.restype = ctypes.c_int
            self.lib.DNSServiceProcessResult.argtypes = [ctypes.c_void_p]; self.lib.DNSServiceProcessResult.restype = ctypes.c_int
            self.lib.DNSServiceRefDeallocate.argtypes = [ctypes.c_void_p]; self.lib.DNSServiceRefDeallocate.restype = None
            started = 0
            for regtype in types:
                if self.stop_event.is_set(): break
                self._start_browse(regtype)
                started += 1
            self._status(f'Bonjour browse active · {started} service types · waiting for results ({self.backend})')
            while not self.stop_event.is_set():
                with self.lock:
                    refs = list(self.refs)
                fd_map = {}
                for ref in refs:
                    try:
                        fd = self.lib.DNSServiceRefSockFD(ref)
                        if fd >= 0: fd_map[fd] = ref
                    except Exception: pass
                if not fd_map:
                    time.sleep(0.1); continue
                try: readable, _, _ = select.select(list(fd_map), [], [], 0.35)
                except (OSError, ValueError):
                    time.sleep(0.1); continue
                for fd in readable:
                    ref = fd_map.get(fd)
                    if ref:
                        err = self.lib.DNSServiceProcessResult(ref)
                        if err:
                            self._status(f'DNS-SD callback processing error {err}')
            self._status('Bonjour browse stopped')
        except Exception as exc:
            self._status(f'Bonjour browse error: {exc}')
            self._emit({'event':'error','error':str(exc),'time':datetime.now().astimezone().isoformat(timespec='seconds')})
        finally:
            with self.lock:
                refs = list(self.refs); self.refs.clear(); self.browse_refs.clear(); self.resolve_refs.clear()
            if self.lib:
                for ref in refs:
                    try: self.lib.DNSServiceRefDeallocate(ref)
                    except Exception: pass
            self.callbacks.clear()
            self.discovered_types.clear()
            self._status('Bonjour discovery worker stopped')

    def _run_cli(self, executable, types):
        """Fallback using Apple's `dns-sd` command when libdns_sd cannot be loaded."""
        self._status(f"Bonjour active discovery using {self.backend}; starting {len(types)} native browse processes")
        for regtype in types:
            if self.stop_event.is_set():
                break
            proc = subprocess.Popen(
                [executable, '-B', regtype, 'local.'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding='utf-8', errors='replace', bufsize=1
            )
            self.cli_processes.append(proc)
            t = threading.Thread(target=self._read_cli_browse, args=(proc, regtype), daemon=True)
            self.cli_threads.append(t); t.start()
        self._status(f"Bonjour browse active · {len(self.cli_processes)} service types · waiting for results (dns-sd fallback)")
        while not self.stop_event.wait(0.2):
            if not any(p.poll() is None for p in self.cli_processes):
                self._status('All dns-sd browse processes exited')
                break
        for proc in list(self.cli_processes):
            try:
                if proc.poll() is None: proc.terminate()
            except Exception: pass
        for proc in list(self.cli_processes):
            try: proc.wait(timeout=1)
            except Exception:
                try: proc.kill()
                except Exception: pass
        self.cli_processes.clear()
        for t in list(self.cli_threads):
            if t.is_alive(): t.join(timeout=0.5)
        self.cli_threads.clear()
        self._status('Bonjour browse stopped')

    def _read_cli_browse(self, proc, regtype):
        # Apple dns-sd output is intended for interactive use and can vary by OS;
        # parse event rows conservatively and preserve names containing spaces.
        try:
            for line in proc.stdout:
                if self.stop_event.is_set(): break
                line = line.strip()
                if not line: continue
                if 'could not' in line.lower() or 'error' in line.lower() and 'interface' in line.lower():
                    self._emit({'event':'error','error':f'dns-sd browse {regtype}: {line}', 'time':datetime.now().astimezone().isoformat(timespec='seconds')})
                    continue
                parts = line.split(None, 6)
                if len(parts) < 7 or parts[1] not in ('Add','Rmv','MoreComing'):
                    continue
                _stamp, action, _flags, ifindex, domain, found_type, name = parts
                found_type = found_type.rstrip('.') or regtype
                domain = domain.rstrip('.') or 'local'
                name = name.strip()
                if not name or name.startswith('Browsing for'):
                    continue
                fullname = f'{name}.{found_type}.{domain}'.replace('..','.')
                is_add = action == 'Add'
                item = {'event':'add' if is_add else 'remove','instance':name,'service_type':found_type,
                        'domain':domain + '.', 'fullname':fullname,'interface_index':int(ifindex) if ifindex.isdigit() else 0,
                        'host':'','port':'','txt':'','resolved':False,'source':'active',
                        'last_seen':datetime.now().astimezone().isoformat(timespec='seconds')}
                self._emit(item)
                if is_add:
                    key=(name, found_type, domain)
                    if not any(getattr(t, '_resolve_key', None) == key for t in self.cli_threads):
                        rt=threading.Thread(target=self._resolve_cli, args=(name,found_type,domain,fullname), daemon=True)
                        rt._resolve_key=key
                        self.cli_threads.append(rt); rt.start()
        except Exception as exc:
            self._emit({'event':'error','error':f'dns-sd output parsing failed for {regtype}: {exc}',
                        'time':datetime.now().astimezone().isoformat(timespec='seconds')})

    def _resolve_cli(self, name, regtype, domain, fullname):
        executable=shutil.which('dns-sd')
        if not executable or self.stop_event.is_set(): return
        proc=None
        try:
            proc=subprocess.Popen([executable,'-L',name,regtype,domain], stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace',bufsize=1)
            self.cli_processes.append(proc)
            deadline=time.monotonic()+5.0
            host=''; port=''; txt=[]
            for line in proc.stdout:
                if self.stop_event.is_set() or time.monotonic()>deadline: break
                line=line.strip()
                m=re.search(r'Can be reached at\s+([^: ]+):(\d+)',line,re.I)
                if m: host=m.group(1).rstrip('.'); port=int(m.group(2)); continue
                m=re.search(r'\bTXT\s+(.+)$',line,re.I)
                if m: txt.append(m.group(1).strip())
                if host:
                    self._emit({'event':'resolved','instance':name,'service_type':regtype,'domain':domain+'.',
                                'fullname':fullname,'interface_index':0,'host':host,'port':port,
                                'txt':'; '.join(txt),'resolved':True,'source':'active',
                                'last_seen':datetime.now().astimezone().isoformat(timespec='seconds')})
                    break
        except Exception as exc:
            self._emit({'event':'resolve_error','fullname':fullname,'error':f'dns-sd resolve failed: {exc}'})
        finally:
            if proc:
                try:
                    if proc.poll() is None:
                        proc.terminate()
                    proc.wait(timeout=0.8)
                except Exception:
                    try:
                        proc.kill()
                        proc.wait(timeout=0.8)
                    except Exception:
                        pass
                try:
                    self.cli_processes.remove(proc)
                except ValueError:
                    pass

    def _start_browse(self, regtype):
        ref = ctypes.c_void_p()
        def callback(sdref, flags, interface_index, error_code, service_name, found_type, domain, context):
            name = self._text(service_name); typ = self._text(found_type) or regtype; dom = self._text(domain) or 'local.'
            if error_code:
                self._emit({'event':'error','error':f'Browse {regtype}: DNS-SD error {error_code}','time':datetime.now().astimezone().isoformat(timespec='seconds')})
                return
            is_add = bool(flags & 0x2) # kDNSServiceFlagsAdd
            fullname = f'{name}.{typ}.{dom}'.replace('..','.')
            item = {'event':'add' if is_add else 'remove','instance':name,'service_type':typ,'domain':dom,
                    'fullname':fullname,'interface_index':int(interface_index),'host':'','port':'','txt':'',
                    'resolved':False,'source':'active','last_seen':datetime.now().astimezone().isoformat(timespec='seconds')}
            self._emit(item)
            if is_add:
                # DNS-SD service enumeration records describe types, not service
                # instances, so they should trigger a new browse rather than resolve.
                if regtype != "_services._dns-sd._udp":
                    self._start_resolve(name, typ, dom, int(interface_index), fullname)
                # DNS-SD service enumeration can reveal service types not in our
                # starter list. Start a browser for each newly enumerated type.
                if regtype == "_services._dns-sd._udp":
                    candidate = name if name.endswith(("._tcp", "._udp")) else f"{name}.{typ}"
                    if candidate.startswith("_") and candidate.endswith(("._tcp", "._udp")) and candidate not in self.discovered_types:
                        self.discovered_types.add(candidate)
                        self._status(f"Discovered service type {candidate}; adding browser")
                        self._start_browse(candidate)
        cb = BROWSE_CB(callback); self.callbacks.append(cb)
        err = self.lib.DNSServiceBrowse(ctypes.byref(ref), 0, self.interface_index, regtype.encode(), None, cb, None)
        if err:
            self._emit({'event':'error','error':f'Could not browse {regtype}: DNS-SD error {err}','time':datetime.now().astimezone().isoformat(timespec='seconds')})
            return
        with self.lock:
            self.refs.append(ref); self.browse_refs[regtype] = ref

    def _start_resolve(self, name, typ, domain, interface_index, fullname):
        if fullname in self.resolve_refs:
            return
        ref = ctypes.c_void_p()
        def callback(sdref, flags, ifidx, error_code, full_name, hosttarget, port, txt_len, txt_record, context):
            if error_code:
                self._emit({'event':'resolve_error','fullname':fullname,'error':f'DNS-SD resolve error {error_code}'})
                return
            txt_items=[]; pos=0
            try:
                raw=ctypes.string_at(txt_record, txt_len) if txt_record and txt_len else b''
                while pos < len(raw):
                    n=raw[pos]; pos+=1
                    txt_items.append(raw[pos:pos+n].decode('utf-8','replace')); pos+=n
            except Exception: pass
            self._emit({'event':'resolved','instance':name,'service_type':typ,'domain':domain,'fullname':self._text(full_name) or fullname,
                        'interface_index':int(ifidx),'host':self._text(hosttarget).rstrip('.'),
                        'port':socket.ntohs(int(port)),'txt':'; '.join(txt_items),'resolved':True,'source':'active',
                        'last_seen':datetime.now().astimezone().isoformat(timespec='seconds')})
        cb=RESOLVE_CB(callback); self.callbacks.append(cb)
        err=self.lib.DNSServiceResolve(ctypes.byref(ref),0,interface_index,name.encode(),typ.encode(),domain.encode(),cb,None)
        if err:
            self._emit({'event':'resolve_error','fullname':fullname,'error':f'Could not resolve {fullname}: DNS-SD error {err}'})
            return
        with self.lock:
            self.refs.append(ref); self.resolve_refs[fullname]=ref
