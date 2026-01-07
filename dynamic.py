import os, re, json, yaml, time, math, socket, sqlite3, hashlib, tempfile, threading, subprocess, select
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

SCORE_MODULES = {'subprocess': 15, 'os': 10, 'socket': 15, 'ctypes': 20, 'requests': 10, 'urllib': 10, 'paramiko': 20, 'child_process': 15, 'fs': 5, 'net': 15, 'libc': 10}
SCORE_FUNCTIONS = {'system': 20, 'popen': 20, 'exec': 25, 'execSync': 25, 'eval': 25, 'connect': 15, 'bind': 15, 'spawn': 15}
MITRE_MAP = {('subprocess', 'Popen'): 'T1059', ('subprocess', 'call'): 'T1059', ('subprocess', 'run'): 'T1059', ('os', 'system'): 'T1059', ('os', 'popen'): 'T1059', ('socket', 'connect'): 'T1071', ('socket', 'bind'): 'T1071', ('child_process', 'exec'): 'T1059', ('child_process', 'spawn'): 'T1059', ('net', 'connect'): 'T1071', ('ctypes', 'CDLL'): 'T1055', ('requests', 'get'): 'T1071.001', ('requests', 'post'): 'T1071.001'}
SUSPICIOUS_IMPORTS = {'setuid': ('T1548', 30, 'Privilege escalation'), 'setreuid': ('T1548', 30, 'Privilege escalation'), 'setgid': ('T1548', 25, 'Privilege escalation'), 'ptrace': ('T1055.008', 20, 'Process injection'), 'system': ('T1059', 15, 'Command execution'), 'execve': ('T1059', 10, 'Program execution'), 'popen': ('T1059', 15, 'Process pipe'), 'socket': ('T1071', 10, 'Network socket'), 'connect': ('T1071', 10, 'Network connect'), 'bind': ('T1071', 10, 'Network bind'), 'init_module': ('T1547.006', 25, 'Kernel module'), 'mprotect': ('T1055', 10, 'Memory protection')}
SUSPICIOUS_STRINGS = [(r'api\.telegram\.org', 'T1102', 20, 'Telegram API'), (r'discord\.com', 'T1102', 15, 'Discord'), (r'/etc/shadow', 'T1003', 25, 'Shadow file'), (r'/etc/passwd', 'T1003', 15, 'Passwd file'), (r'\.ssh/', 'T1552.004', 20, 'SSH directory'), (r'LD_PRELOAD', 'T1574.006', 15, 'LD_PRELOAD'), (r'PTRACE_TRACEME', 'T1622', 15, 'Anti-debugging')]
SUSPICIOUS_TLDS = {'.shop', '.fun', '.xyz', '.top', '.club', '.online', '.site', '.work', '.click', '.link', '.gq', '.ml', '.cf', '.tk', '.ga', '.pw'}
SUSPICIOUS_HOSTS = {'api.telegram.org': ('T1102', 20, 'Telegram Bot API (C2)'), 'discord.com': ('T1102', 15, 'Discord (exfiltration)'), 'pastebin.com': ('T1102', 15, 'Pastebin (payload)'), 'raw.githubusercontent.com': ('T1105', 10, 'GitHub raw'), 'ipinfo.io': ('T1016', 10, 'IP geolocation'), 'ip-api.com': ('T1016', 10, 'IP geolocation')}
FIREJAIL_PROFILE = "quiet\nnoprofile\nprivate-tmp\nnoroot\nnonewprivs\nseccomp\ncaps.drop all\nrlimit-cpu 30\nrlimit-fsize 50000000\n"
FILE_TYPE_MAP = {'.py': 'python', '.pyw': 'python', '.js': 'javascript', '.mjs': 'javascript', '.sh': 'shell', '.bash': 'shell'}

@dataclass
class ThreatEvent:
    source: str
    event_type: str
    details: str
    score: int
    mitre: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class YaraMatch:
    rule: str
    description: str
    score: int
    mitre: str = ""
    strings: List[str] = field(default_factory=list)

@dataclass
class AnalysisResult:
    verdict: str
    threat_score: int
    reasons: List[str]
    events: List[ThreatEvent]
    duration: float
    file_type: str
    file_hash: str
    yara_matches: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

class LogServer:
    def __init__(self):
        self.socket_path = f"/tmp/sandbox_{os.getpid()}_{int(time.time())}.sock"
        self.events: List[ThreatEvent] = []
        self._server_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()
    
    def start(self) -> str:
        if os.path.exists(self.socket_path): os.unlink(self.socket_path)
        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(self.socket_path)
        self._server_socket.listen(5)
        self._server_socket.setblocking(False)
        os.chmod(self.socket_path, 0o777)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self.socket_path
    
    def _accept_loop(self):
        while self._running:
            try:
                readable, _, _ = select.select([self._server_socket], [], [], 0.5)
                if readable:
                    client, _ = self._server_socket.accept()
                    threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()
            except: break
    
    def _handle_client(self, client: socket.socket):
        buffer = ""
        client.setblocking(False)
        while self._running:
            try:
                readable, _, _ = select.select([client], [], [], 0.5)
                if readable:
                    data = client.recv(4096)
                    if not data: break
                    buffer += data.decode('utf-8', errors='ignore')
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        if line.strip(): self._process_event(line.strip())
            except: break
        try: client.close()
        except: pass
    
    def _process_event(self, line: str):
        try:
            data = json.loads(line)
            module, function, cmd = data.get('module', ''), data.get('function', ''), data.get('cmd', '')
            details = f"exec: {cmd[:100]}" if cmd else f"{module}.{function}" if module else data.get('type', '')
            with self._lock:
                self.events.append(ThreatEvent(source='tracer', event_type=data.get('type', 'call'), details=details,
                    score=min(SCORE_MODULES.get(module, 0) + SCORE_FUNCTIONS.get(function, 0), 30), mitre=MITRE_MAP.get((module, function))))
        except: pass
    
    def get_events(self) -> List[ThreatEvent]:
        with self._lock: return list(self.events)
    
    def stop(self):
        self._running = False
        try: self._server_socket.close()
        except: pass
        if self._thread and self._thread.is_alive(): self._thread.join(timeout=2)
        try: os.unlink(self.socket_path)
        except: pass

class NetworkMonitor:
    def __init__(self, interface: str = "any"):
        self.interface = interface
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._events: List[ThreatEvent] = []
        self._seen_domains: Set[str] = set()
        self._lock = threading.Lock()
    
    def start(self) -> bool:
        if self._running: return True
        try:
            self._proc = subprocess.Popen(['tcpdump', '-i', self.interface, '-l', '-n', '-q', 'port 53 or port 80 or port 443'],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            self._running = True
            self._thread = threading.Thread(target=self._read_loop, daemon=True)
            self._thread.start()
            return True
        except: return False
    
    def _read_loop(self):
        if not self._proc or not self._proc.stdout: return
        for line in self._proc.stdout:
            if not self._running: break
            event = self._parse_line(line.strip())
            if event:
                with self._lock: self._events.append(event)
    
    def _parse_line(self, line: str) -> Optional[ThreatEvent]:
        dest_match = re.search(r'>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):', line)
        if not dest_match: return None
        if int(dest_match.group(2)) == 53:
            domain_match = re.search(r'\?\s*([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]+)', line)
            if domain_match:
                domain = domain_match.group(1).lower().rstrip('.')
                if domain not in self._seen_domains:
                    self._seen_domains.add(domain)
                    for tld in SUSPICIOUS_TLDS:
                        if domain.endswith(tld):
                            return ThreatEvent(source='network', event_type='suspicious_dns', details=f"Suspicious TLD: {domain}", score=15, mitre='T1071.004')
                    for host, (mitre, score, desc) in SUSPICIOUS_HOSTS.items():
                        if host in domain:
                            return ThreatEvent(source='network', event_type='suspicious_dns', details=f"{desc}: {domain}", score=score, mitre=mitre)
        return None
    
    def get_events(self) -> List[ThreatEvent]:
        with self._lock: return list(self._events)
    
    def stop(self):
        self._running = False
        try: self._proc.terminate(); self._proc.wait(timeout=2)
        except: pass
    
    @staticmethod
    def is_available() -> bool:
        try: return subprocess.run(['which', 'tcpdump'], capture_output=True, timeout=5).returncode == 0
        except: return False

class YaraScanner:
    def __init__(self, rules_dir: str = "yara_rules"):
        self.rules_dir, self.rules, self._available = rules_dir, None, False
        try:
            import yara
            if os.path.exists(rules_dir):
                rule_files = {f: os.path.join(rules_dir, f) for f in os.listdir(rules_dir) if f.endswith(('.yar', '.yara'))}
                if rule_files: self.rules = yara.compile(filepaths=rule_files)
            self._available = self.rules is not None
        except: pass
    
    @property
    def available(self) -> bool: return self._available
    
    def scan(self, file_path: str) -> List[YaraMatch]:
        if not self._available or not os.path.exists(file_path): return []
        try:
            matches = []
            for m in self.rules.match(file_path):
                meta = m.meta if hasattr(m, 'meta') else {}
                matches.append(YaraMatch(rule=m.rule, description=meta.get('description', m.rule), score=int(meta.get('score', 10)),
                    mitre=meta.get('mitre', ''), strings=[s.identifier for s in (m.strings[:5] if hasattr(m, 'strings') else [])]))
            return matches
        except: return []

class ELFAnalyzer:
    def __init__(self):
        try: from elftools.elf.elffile import ELFFile; self._available = True
        except: self._available = False
    
    @property
    def available(self) -> bool: return self._available
    
    def analyze(self, file_path: str) -> List[ThreatEvent]:
        if not self._available or not os.path.exists(file_path): return []
        events = []
        try:
            from elftools.elf.elffile import ELFFile
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                events.extend(self._analyze_imports(elf))
                f.seek(0)
                events.extend(self._analyze_strings(f.read()))
                events.extend(self._analyze_entropy(elf))
        except: pass
        return events
    
    def _analyze_imports(self, elf) -> List[ThreatEvent]:
        events, found = [], set()
        try:
            for section in elf.iter_sections():
                if section.name == '.dynstr':
                    for s in section.data().split(b'\x00'):
                        sym = s.decode('utf-8', errors='ignore')
                        if sym in SUSPICIOUS_IMPORTS and sym not in found:
                            found.add(sym)
                            mitre, score, desc = SUSPICIOUS_IMPORTS[sym]
                            events.append(ThreatEvent(source='elf', event_type='import', details=f"{sym}: {desc}", score=score, mitre=mitre))
        except: pass
        return events
    
    def _analyze_strings(self, data: bytes) -> List[ThreatEvent]:
        events, strings, current = [], [], []
        for b in data:
            if 32 <= b <= 126: current.append(chr(b))
            else:
                if len(current) >= 4: strings.append(''.join(current))
                current = []
        all_strings = '\n'.join(strings)
        for pattern, mitre, score, desc in SUSPICIOUS_STRINGS:
            if re.search(pattern, all_strings, re.IGNORECASE):
                events.append(ThreatEvent(source='elf', event_type='string', details=desc, score=score, mitre=mitre))
        return events
    
    def _analyze_entropy(self, elf) -> List[ThreatEvent]:
        events = []
        for section in elf.iter_sections():
            if section.name in ['.text', '.data']:
                try:
                    data = section.data()
                    if len(data) > 100:
                        counts = [0] * 256
                        for b in data: counts[b] += 1
                        entropy = -sum(c/len(data) * math.log2(c/len(data)) for c in counts if c > 0)
                        if entropy > 7.5:
                            events.append(ThreatEvent(source='elf', event_type='entropy', details=f"High entropy {section.name}: {entropy:.2f}", score=15, mitre='T1027'))
                except: pass
        return events

class RuleEngine:
    def __init__(self, patterns_file: str = "patterns.yaml"):
        self.patterns: Dict = {}
        if os.path.exists(patterns_file):
            try:
                with open(patterns_file, 'r', encoding='utf-8') as f: self.patterns = yaml.safe_load(f) or {}
            except: pass
    
    def match_script(self, language: str, code: str) -> List[ThreatEvent]:
        events = []
        for category, patterns in self.patterns.get('scripts', {}).get(language, {}).items():
            if isinstance(patterns, list):
                for p in patterns:
                    if isinstance(p, dict) and p.get('pattern'):
                        try:
                            if re.search(p['pattern'], code):
                                events.append(ThreatEvent(source='script', event_type=category, details=p.get('description', 'Suspicious pattern'), score=p.get('score', 10), mitre=p.get('mitre')))
                        except: pass
        return events
    
    def get_threshold(self, level: str) -> int:
        return self.patterns.get('verdict_thresholds', {}).get(level, 50)

class PythonTracer:
    TRACER_CODE = '''
import os as _os
_sock = _os.environ.get('SANDBOX_SOCKET')
if _sock:
    try:
        import hunter as _h, socket as _s, json as _j
        _c = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
        _c.connect(_sock)
        _c.setblocking(False)
        def _send(e):
            try: _c.send((_j.dumps({"type":e.kind,"module":str(e.module or ""),"function":str(e.function or "")})+"\\n").encode())
            except: pass
        _h.trace(_h.Q(module_startswith=("os","subprocess","socket","requests","urllib","ctypes"),kind="call"),action=_send)
    except: pass
'''
    def __init__(self): self._temp_files: List[str] = []
    
    def wrap_script(self, script_path: str) -> Tuple[List[str], Optional[str]]:
        try:
            with open(script_path, 'r', encoding='utf-8', errors='ignore') as f: code = f.read()
            temp = os.path.join(tempfile.gettempdir(), f"traced_{os.getpid()}_{os.path.basename(script_path)}")
            with open(temp, 'w', encoding='utf-8') as f: f.write(self.TRACER_CODE + '\n' + code)
            os.chmod(temp, 0o755)
            self._temp_files.append(temp)
            return ['python3', temp], temp
        except: return ['python3', script_path], None
    
    def cleanup(self):
        for f in self._temp_files:
            try: os.unlink(f)
            except: pass
        self._temp_files = []

class JSTracer:
    TRACER_JS = '''const net=require("net"),sp=process.env.SANDBOX_SOCKET;
if(sp){let c;try{c=net.createConnection(sp);c.on("error",()=>{})}catch(e){}
const send=(t,d)=>{if(c&&c.writable)try{c.write(JSON.stringify({type:t,module:d.m||"",function:d.f||"",cmd:d.c||""})+"\\n")}catch(e){}};
try{const cp=require("child_process");["exec","execSync","spawn","spawnSync"].forEach(fn=>{const o=cp[fn];cp[fn]=function(...a){send("exec",{m:"child_process",f:fn,c:String(a[0]).slice(0,200)});return o.apply(this,a)}})}catch(e){}
try{const fs=require("fs");["writeFile","writeFileSync","unlink"].forEach(fn=>{const o=fs[fn];fs[fn]=function(p,...a){send("file",{m:"fs",f:fn,c:String(p)});return o.apply(this,[p,...a])}})}catch(e){}}'''
    def __init__(self): self._temp_files: List[str] = []
    
    def wrap_script(self, script_path: str) -> Tuple[List[str], Optional[str]]:
        try:
            temp = os.path.join(tempfile.gettempdir(), f"tracer_{os.getpid()}.js")
            with open(temp, 'w', encoding='utf-8') as f: f.write(self.TRACER_JS)
            self._temp_files.append(temp)
            return ['node', '--require', temp, script_path], temp
        except: return ['node', script_path], None
    
    def cleanup(self):
        for f in self._temp_files:
            try: os.unlink(f)
            except: pass
        self._temp_files = []

class SandboxRunner:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.py_tracer = PythonTracer()
        self.js_tracer = JSTracer()
        self._profile_path: Optional[str] = None
    
    def _detect_type(self, path: str) -> str:
        ext = os.path.splitext(path)[1].lower()
        if ext in FILE_TYPE_MAP: return FILE_TYPE_MAP[ext]
        try:
            info = subprocess.run(['file', '-b', path], capture_output=True, text=True, timeout=5).stdout.lower()
            if 'elf' in info: return 'elf_x64' if 'x86-64' in info else 'elf'
            if 'python' in info: return 'python'
            if 'shell' in info: return 'shell'
        except: pass
        return 'unknown'
    
    def _is_firejail_available(self) -> bool:
        try: return subprocess.run(['which', 'firejail'], capture_output=True, timeout=5).returncode == 0
        except: return False
    
    def _create_profile(self) -> str:
        if not self._profile_path:
            self._profile_path = os.path.join(tempfile.gettempdir(), f"sandbox_{os.getpid()}.profile")
            with open(self._profile_path, 'w') as f: f.write(FIREJAIL_PROFILE)
        return self._profile_path
    
    def run(self, file_path: str, use_sandbox: bool = True, use_tracer: bool = True) -> Dict:
        if not os.path.exists(file_path): return {'error': f'File not found: {file_path}'}
        file_type = self._detect_type(file_path)
        if file_type.startswith('elf') or file_type == 'shell':
            try: os.chmod(file_path, 0o755)
            except: pass
        log_server, socket_path, temp_file = None, None, None
        env = os.environ.copy()
        if use_tracer and file_type in ['python', 'javascript']:
            log_server = LogServer()
            socket_path = log_server.start()
            env['SANDBOX_SOCKET'] = socket_path
            base_cmd, temp_file = (self.py_tracer if file_type == 'python' else self.js_tracer).wrap_script(file_path)
        else:
            base_cmd = {'python': ['python3', file_path], 'javascript': ['node', file_path], 'shell': ['/bin/bash', file_path]}.get(file_type, [file_path])
        if use_sandbox and self._is_firejail_available():
            profile = self._create_profile()
            cmd = ['firejail', f'--profile={profile}', '--net=none']
            if socket_path: cmd.extend([f'--whitelist={socket_path}', '--whitelist=/tmp'])
            if temp_file: cmd.append(f'--whitelist={temp_file}')
            cmd.extend(base_cmd)
        else:
            cmd = base_cmd
        start = time.time()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout, cwd=os.path.dirname(file_path) or '.', env=env)
            duration = time.time() - start
            events = []
            if log_server:
                time.sleep(0.1)
                events = log_server.get_events()
                log_server.stop()
            self.py_tracer.cleanup()
            self.js_tracer.cleanup()
            return {'exit_code': result.returncode, 'stdout': result.stdout[:10000], 'stderr': result.stderr[:10000], 'duration': duration, 'file_type': file_type, 'events': events, 'tracer_used': socket_path is not None}
        except subprocess.TimeoutExpired:
            events = log_server.get_events() if log_server else []
            if log_server: log_server.stop()
            self.py_tracer.cleanup()
            self.js_tracer.cleanup()
            return {'exit_code': -1, 'stderr': 'Timeout', 'duration': self.timeout, 'file_type': file_type, 'timeout': True, 'events': events}
        except Exception as e:
            if log_server: log_server.stop()
            self.py_tracer.cleanup()
            self.js_tracer.cleanup()
            return {'error': str(e), 'file_type': file_type, 'events': []}

class ThreatScorer:
    def __init__(self, rule_engine: Optional[RuleEngine] = None):
        self.events: List[ThreatEvent] = []
        self.total_score = 0
        self.rule_engine = rule_engine or RuleEngine()
    
    def add_event(self, event: ThreatEvent):
        self.events.append(event)
        self.total_score += event.score
    
    def add_events(self, events: List[ThreatEvent]):
        for e in events: self.add_event(e)
    
    def add_yara_matches(self, matches: List[YaraMatch]):
        for m in matches:
            self.add_event(ThreatEvent(source='yara', event_type='signature', details=f"{m.rule}: {m.description}", score=m.score, mitre=m.mitre or None))
    
    def get_verdict(self) -> str:
        clean, suspicious = self.rule_engine.get_threshold('clean'), self.rule_engine.get_threshold('suspicious')
        if self.total_score <= clean: return "CLEAN"
        if self.total_score <= suspicious: return "SUSPICIOUS"
        return "MALICIOUS"
    
    def get_reasons(self) -> List[str]:
        return [f"[{e.source.upper()}] {e.details}" + (f" ({e.mitre})" if e.mitre else "") for e in self.events]
    
    def get_mitre_techniques(self) -> List[str]:
        return list({e.mitre for e in self.events if e.mitre})

class AnalysisDB:
    def __init__(self, db_path: str = "logs/dynamic_analysis.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        with sqlite3.connect(db_path) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS analyses (id INTEGER PRIMARY KEY AUTOINCREMENT, file_hash TEXT NOT NULL, file_name TEXT, file_type TEXT, verdict TEXT, threat_score INTEGER, duration REAL, reasons TEXT, yara_matches TEXT, mitre_techniques TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    
    def save(self, path: str, result: AnalysisResult) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("INSERT INTO analyses (file_hash, file_name, file_type, verdict, threat_score, duration, reasons, yara_matches, mitre_techniques) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (result.file_hash, os.path.basename(path), result.file_type, result.verdict, result.threat_score, result.duration, json.dumps(result.reasons), json.dumps(result.yara_matches), json.dumps(result.mitre_techniques)))
            return cur.lastrowid
    
    def get_by_hash(self, file_hash: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM analyses WHERE file_hash=? ORDER BY created_at DESC LIMIT 1", (file_hash,)).fetchone()
        if row:
            return {k: json.loads(row[k]) if k in ('reasons', 'yara_matches', 'mitre_techniques') and row[k] else row[k] for k in row.keys()}
        return None

class DynamicAnalyzer:
    def __init__(self, timeout: int = 30, db_path: str = "logs/dynamic_analysis.db", yara_dir: str = "yara_rules", patterns_file: str = "patterns.yaml"):
        self.timeout = timeout
        self.yara = YaraScanner(yara_dir)
        self.rules = RuleEngine(patterns_file)
        self.sandbox = SandboxRunner(timeout)
        self.elf = ELFAnalyzer()
        self.db = AnalysisDB(db_path)
    
    def _hash_file(self, path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''): h.update(chunk)
            return h.hexdigest()
        except: return ''
    
    def run(self, file_path: str, use_cache: bool = True, use_tracer: bool = True, use_network_monitor: bool = False) -> Dict:
        start = time.time()
        if not os.path.exists(file_path): return {'verdict': 'ERROR', 'threat_score': 0, 'reasons': ['File not found']}
        file_hash = self._hash_file(file_path)
        if use_cache and file_hash:
            cached = self.db.get_by_hash(file_hash)
            if cached: cached['cached'] = True; return cached
        scorer = ThreatScorer(self.rules)
        file_type = self.sandbox._detect_type(file_path)
        scorer.add_yara_matches(self.yara.scan(file_path))
        if file_type in ['python', 'javascript', 'shell']:
            try:
                with open(file_path, 'r', errors='ignore') as f: scorer.add_events(self.rules.match_script(file_type, f.read()))
            except: pass
        elif file_type.startswith('elf'):
            scorer.add_events(self.elf.analyze(file_path))
        net_monitor = None
        if use_network_monitor and NetworkMonitor.is_available():
            net_monitor = NetworkMonitor()
            net_monitor.start()
        sandbox_result = {}
        if file_type in ['python', 'javascript', 'shell', 'elf', 'elf_x64']:
            sandbox_result = self.sandbox.run(file_path, use_tracer=use_tracer)
            scorer.add_events(sandbox_result.get('events', []))
        if net_monitor:
            time.sleep(0.5)
            scorer.add_events(net_monitor.get_events())
            net_monitor.stop()
        duration = time.time() - start
        result = AnalysisResult(verdict=scorer.get_verdict(), threat_score=min(scorer.total_score, 100), reasons=scorer.get_reasons(), events=scorer.events, duration=duration, file_type=file_type, file_hash=file_hash, yara_matches=[m.rule for m in self.yara.scan(file_path)], mitre_techniques=scorer.get_mitre_techniques())
        try: self.db.save(file_path, result)
        except: pass
        return {'verdict': result.verdict, 'threat_score': result.threat_score, 'duration': result.duration, 'reasons': result.reasons, 'file_type': result.file_type, 'file_hash': result.file_hash, 'yara_matches': result.yara_matches, 'mitre_techniques': result.mitre_techniques, 'sandbox': sandbox_result, 'event_count': len(scorer.events)}
    
    def get_status(self) -> Dict:
        return {'yara_available': self.yara.available, 'elf_analyzer': self.elf.available, 'firejail': self.sandbox._is_firejail_available(), 'tcpdump': NetworkMonitor.is_available(), 'rules_loaded': len(self.rules.patterns) > 0}
