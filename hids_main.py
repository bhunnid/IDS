"""
hids_main.py  ─  Ulinzi HIDS Detection Engine
===============================================
Importable module. Started automatically by app.py as a background thread.
Can also run headless:  sudo python3 hids_main.py

ALERT LEVELS (lowest → highest)
  INFO      System events (start / stop / mode change)
  LOW       Mild anomaly worth watching
  MEDIUM    Suspicious activity – investigate soon
  HIGH      Likely attack in progress
  CRITICAL  Severe / confirmed intrusion

DETECTION RULES
  H1  Brute-force login      (/var/log/auth.log failure rate)
  H2  Privilege escalation   (sudo/su event rate)
  H3  Process anomaly        (new-process spawn rate via psutil)
  H4  File integrity         (SHA-256 change on critical files)
  N1  SYN flood              (SYN rate + SYN ratio)
  N2  UDP flood              (UDP packet rate)
  N3  ICMP flood             (ICMP packet rate)
  N4  Port scan              (distinct dst-ports per source IP)

ALERT FILE FORMAT
  [YYYY-MM-DD HH:MM:SS] LEVEL:<level> RULE:<tag> | <detail>
"""

from __future__ import annotations

import os, re, sys, time, signal, socket, struct, hashlib
import logging, subprocess, threading, collections
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Optional, Set, Tuple

# ── optional psutil ───────────────────────────────────────────────────────────
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

# =============================================================================
# CONFIGURATION
# =============================================================================
INTERFACE            = None   # None = auto-detect from routing table
BASELINE_SECONDS     = 60     # learning window
WINDOW_SECONDS       = 1      # measurement interval (1 s = near-instant alerts)
THRESHOLD_MULTIPLIER = 3      # threshold = max(hard_floor, p95 × multiplier)

# Network hard floors (packets / second)
SYN_FLOOR   = 100
UDP_FLOOR   = 500
ICMP_FLOOR  = 50
TOTAL_FLOOR = 800
SYN_RATIO_MIN       = 0.60   # fraction of TCP that must be SYN for a flood alert
PORT_SCAN_THRESHOLD = 20     # distinct dst-ports from one IP in a 1-s window

# Host hard floors (events per 1-s window)
AUTH_FAIL_FLOOR     = 3
SUDO_EVENT_FLOOR    = 5
PROCESS_SPAWN_FLOOR = 20

CONFIRM_WINDOWS = 2           # consecutive windows before a network alert fires
COOLDOWN_SECS   = 30          # minimum seconds between repeated alerts for same rule

MONITORED_FILES: List[str] = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/hosts",  "/etc/ssh/sshd_config", "/etc/crontab",
]
FILE_CHECK_INTERVAL = 5       # seconds between file-integrity polls

AUTH_LOG_CANDIDATES = [
    "/var/log/auth.log",   # Debian / Ubuntu / Kali
    "/var/log/secure",     # RHEL / CentOS / Fedora
    "/var/log/messages",
]

ALERT_LOG = "alerts.log"
INFO_LOG  = "hids.log"

# Severity scaling relative to the hard floor
_LEVEL_RATIO = {"LOW": 1.0, "MEDIUM": 2.5, "HIGH": 5.0, "CRITICAL": 10.0}

# =============================================================================
# HELPERS
# =============================================================================

def rate_to_level(value: float, floor: float) -> str:
    r = value / max(floor, 1)
    if r >= _LEVEL_RATIO["CRITICAL"]: return "CRITICAL"
    if r >= _LEVEL_RATIO["HIGH"]:     return "HIGH"
    if r >= _LEVEL_RATIO["MEDIUM"]:   return "MEDIUM"
    return "LOW"

# =============================================================================
# LOGGING
# =============================================================================

def _setup_logging() -> None:
    fmt  = logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s",
                             datefmt="%Y-%m-%d %H:%M:%S")
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    fh = RotatingFileHandler(INFO_LOG, maxBytes=5_000_000, backupCount=2)
    fh.setLevel(logging.DEBUG); fh.setFormatter(fmt); root.addHandler(fh)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO);  ch.setFormatter(fmt); root.addHandler(ch)

_setup_logging()
log = logging.getLogger("hids")

def write_alert(level: str, rule: str, detail: str) -> None:
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] LEVEL:{level} RULE:{rule} | {detail}"
    try:
        with open(ALERT_LOG, "a") as fh:
            fh.write(line + "\n")
    except OSError as e:
        log.error("Cannot write alert: %s", e)
    log.warning(">>> %s | %s | %s", level, rule, detail)

# =============================================================================
# NETWORK — INTERFACE DETECTION
# =============================================================================

_VIRTUAL = ("lo","virbr","docker","br-","veth","tun","tap","vmnet","vboxnet","dummy","sit")

def _is_virtual(n: str) -> bool:
    return any(n.startswith(p) for p in _VIRTUAL)

def _candidate_interfaces() -> List[str]:
    seen: Set[str] = set(); result: List[str] = []
    def add(n: str) -> None:
        n = n.strip()
        if n and n not in seen and not _is_virtual(n):
            seen.add(n); result.append(n)
    try:
        out = subprocess.check_output(["ip","route","show","default"],
                                      stderr=subprocess.DEVNULL, timeout=3).decode()
        toks = out.split()
        for i,t in enumerate(toks):
            if t == "dev" and i+1 < len(toks): add(toks[i+1])
    except Exception: pass
    try:
        for _,n in socket.if_nameindex(): add(n)
    except Exception: pass
    try:
        with open("/proc/net/dev") as fh:
            for line in fh:
                if ":" in line: add(line.split(":")[0].strip())
    except OSError: pass
    for fb in ("eth0","ens33","ens3","enp0s3","ens160","wlan0"): add(fb)
    return result

def _can_bind(iface: str) -> bool:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((iface, 0)); s.close(); return True
    except OSError: return False

def get_interface() -> str:
    if INTERFACE: return INTERFACE
    cands = _candidate_interfaces()
    if os.geteuid() == 0:
        for iface in cands:
            if _can_bind(iface):
                log.info("Network interface: %s", iface); return iface
    return cands[0] if cands else "eth0"

# =============================================================================
# NETWORK — PACKET PARSING
# =============================================================================

PROTO_TCP=6; PROTO_UDP=17; PROTO_ICMP=1
ETH_P_IP=0x0800; ETH_P_ALL=0x0003

class Packet:
    __slots__ = ("src_ip","proto","dport","is_syn")
    def __init__(self, src_ip:str, proto:int, dport:int=0, is_syn:bool=False):
        self.src_ip=src_ip; self.proto=proto; self.dport=dport; self.is_syn=is_syn

def parse_packet(raw: bytes) -> Optional[Packet]:
    if len(raw) < 34: return None
    if struct.unpack_from("!H", raw, 12)[0] != ETH_P_IP: return None
    ip = raw[14:]
    if len(ip) < 20: return None
    ihl=( ip[0]&0x0F)*4; proto=ip[9]
    try: src_ip = socket.inet_ntoa(ip[12:16])
    except OSError: return None
    payload=ip[ihl:]; dport=0; is_syn=False
    if proto==PROTO_TCP and len(payload)>=14:
        dport=struct.unpack_from("!H",payload,2)[0]
        flags=payload[13]; is_syn=bool(flags&0x02) and not bool(flags&0x10)
    elif proto==PROTO_UDP and len(payload)>=4:
        dport=struct.unpack_from("!H",payload,2)[0]
    return Packet(src_ip, proto, dport, is_syn)

# =============================================================================
# NETWORK — PACKET BUFFER + SNIFFER
# =============================================================================

class PacketBuffer:
    def __init__(self):
        self._lock=threading.Lock(); self._pkts:List[Packet]=[]
    def put(self, p:Packet):
        with self._lock: self._pkts.append(p)
    def drain(self) -> List[Packet]:
        with self._lock:
            out,self._pkts=self._pkts,[]; return out

class Sniffer(threading.Thread):
    def __init__(self, buf:PacketBuffer, iface:str):
        super().__init__(daemon=True, name="sniffer")
        self._buf=buf; self._iface=iface
        self._stop=threading.Event(); self._sock=None

    def run(self):
        try:
            self._sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(ETH_P_ALL))
            self._sock.bind((self._iface,0))
            self._sock.settimeout(0.3)
            log.info("Sniffer bound to: %s", self._iface)
        except PermissionError:
            log.critical("Permission denied — run with: sudo python3 app.py")
            os._exit(1)
        except OSError as e:
            log.critical("Cannot bind to %r: %s", self._iface, e)
            os._exit(1)
        while not self._stop.is_set():
            try:
                raw=self._sock.recv(65535)
                p=parse_packet(raw)
                if p: self._buf.put(p)
            except socket.timeout: continue
            except OSError: break
        if self._sock: self._sock.close()

    def stop(self): self._stop.set()

# =============================================================================
# NETWORK — WINDOW STATS
# =============================================================================

class NetStats:
    __slots__=("total_rate","syn_rate","udp_rate","icmp_rate",
               "tcp_count","syn_count","udp_count","icmp_count",
               "syn_ratio","src_port_spread")
    def __init__(self):
        self.total_rate=0.0;self.syn_rate=0.0;self.udp_rate=0.0;self.icmp_rate=0.0
        self.tcp_count=0;self.syn_count=0;self.udp_count=0;self.icmp_count=0
        self.syn_ratio=0.0; self.src_port_spread:Dict[str,int]={}

def compute_net_stats(packets:List[Packet], w:float) -> NetStats:
    ns=NetStats(); src_ports:Dict[str,Set[int]]=collections.defaultdict(set)
    for p in packets:
        if p.proto==PROTO_TCP:
            ns.tcp_count+=1; src_ports[p.src_ip].add(p.dport)
            if p.is_syn: ns.syn_count+=1
        elif p.proto==PROTO_UDP:
            ns.udp_count+=1; src_ports[p.src_ip].add(p.dport)
        elif p.proto==PROTO_ICMP: ns.icmp_count+=1
    ns.total_rate=len(packets)/w; ns.syn_rate=ns.syn_count/w
    ns.udp_rate=ns.udp_count/w;   ns.icmp_rate=ns.icmp_count/w
    ns.syn_ratio=(ns.syn_count/ns.tcp_count) if ns.tcp_count else 0.0
    ns.src_port_spread={ip:len(ports) for ip,ports in src_ports.items()}
    return ns

# =============================================================================
# HOST — AUTH LOG MONITOR  (H1 brute-force, H2 priv-esc)
# =============================================================================

_AUTH_FAIL_RE=re.compile(
    r"(Failed password|authentication failure|Invalid user|FAILED LOGIN|"
    r"pam_unix.*authentication failure|Connection closed by authenticating user|"
    r"Too many authentication)",re.IGNORECASE)
_SUDO_RE=re.compile(
    r"(sudo:.*COMMAND|su:.*session opened|sudo:.*authentication failure|"
    r"sudo:.*incorrect password)",re.IGNORECASE)

class AuthLogMonitor:
    def __init__(self):
        self._path=self._find(); self._pos=0
        self._fail=0; self._sudo=0; self._lock=threading.Lock()
        if self._path:
            try: self._pos=os.path.getsize(self._path)
            except OSError: pass
            log.info("Auth log: %s (offset %d)", self._path, self._pos)
        else: log.warning("No auth log found — H1/H2 disabled")

    @staticmethod
    def _find() -> Optional[str]:
        for p in AUTH_LOG_CANDIDATES:
            if os.path.exists(p) and os.access(p,os.R_OK): return p
        return None

    def poll(self):
        if not self._path: return
        try: size=os.path.getsize(self._path)
        except OSError: return
        if size<self._pos: self._pos=0
        if size==self._pos: return
        try:
            with open(self._path,"r",errors="replace") as fh:
                fh.seek(self._pos); chunk=fh.read(size-self._pos)
                self._pos=fh.tell()
        except OSError: return
        f=d=0
        for line in chunk.splitlines():
            if _AUTH_FAIL_RE.search(line): f+=1
            if _SUDO_RE.search(line):      d+=1
        with self._lock: self._fail+=f; self._sudo+=d

    def drain(self) -> Tuple[int,int]:
        with self._lock:
            f,s=self._fail,self._sudo; self._fail=self._sudo=0; return f,s

    def available(self) -> bool: return self._path is not None

# =============================================================================
# HOST — PROCESS MONITOR  (H3)
# =============================================================================

class ProcessMonitor:
    def __init__(self):
        self._ok=PSUTIL_OK; self._pids:Set[int]=set()
        if self._ok:
            try: self._pids={p.pid for p in psutil.process_iter()}; log.info("Process monitor active (%d PIDs)",len(self._pids))
            except Exception: self._ok=False
        if not self._ok: log.warning("psutil unavailable — H3 disabled")

    def count_new(self) -> int:
        if not self._ok: return 0
        try: cur={p.pid for p in psutil.process_iter()}
        except Exception: return 0
        new=cur-self._pids; self._pids=cur; return len(new)

    def available(self) -> bool: return self._ok

# =============================================================================
# HOST — FILE INTEGRITY MONITOR  (H4)
# =============================================================================

class FileIntegrityMonitor:
    def __init__(self):
        self._hashes:Dict[str,str]={}; self._skip:Set[str]=set()
        self._pending:List[Tuple[str,str]]=[]
        self._lock=threading.Lock(); self._stop=threading.Event()
        self._thread=threading.Thread(target=self._run,daemon=True,name="fim")
        self._baseline(); self._thread.start()
        log.info("FIM: watching %d file(s)", len(self._hashes))

    @staticmethod
    def _hash(path:str) -> Optional[str]:
        try:
            h=hashlib.sha256()
            with open(path,"rb") as fh:
                for chunk in iter(lambda:fh.read(65536),b""): h.update(chunk)
            return h.hexdigest()
        except (OSError,PermissionError): return None

    def _baseline(self):
        for p in MONITORED_FILES:
            h=self._hash(p)
            if h is None: self._skip.add(p)
            else: self._hashes[p]=h

    def _run(self):
        while not self._stop.is_set():
            self._stop.wait(FILE_CHECK_INTERVAL)
            if self._stop.is_set(): break
            for path,known in list(self._hashes.items()):
                cur=self._hash(path)
                if cur and cur!=known:
                    detail=f"path={path} prev_hash={known[:16]}... new_hash={cur[:16]}..."
                    with self._lock: self._pending.append((path,detail))
                    self._hashes[path]=cur

    def drain(self) -> List[Tuple[str,str]]:
        with self._lock:
            out,self._pending=self._pending,[]; return out

    def stop(self): self._stop.set()

# =============================================================================
# ADAPTIVE BASELINE
# =============================================================================

class Baseline:
    def __init__(self):
        self._s:Dict[str,List[float]]={
            "total":[],"syn":[],"udp":[],"icmp":[],
            "auth_fail":[],"sudo":[],"proc":[]}
        self.thr_total=float(TOTAL_FLOOR); self.thr_syn=float(SYN_FLOOR)
        self.thr_udp=float(UDP_FLOOR);     self.thr_icmp=float(ICMP_FLOOR)
        self.thr_auth_fail=float(AUTH_FAIL_FLOOR)
        self.thr_sudo=float(SUDO_EVENT_FLOOR)
        self.thr_proc=float(PROCESS_SPAWN_FLOOR)

    def record(self,ns:NetStats,af:int,sd:int,pr:int):
        self._s["total"].append(ns.total_rate); self._s["syn"].append(ns.syn_rate)
        self._s["udp"].append(ns.udp_rate);     self._s["icmp"].append(ns.icmp_rate)
        self._s["auth_fail"].append(float(af))
        self._s["sudo"].append(float(sd)); self._s["proc"].append(float(pr))

    @staticmethod
    def _p95(v:List[float]) -> float:
        if not v: return 0.0
        s=sorted(v); return s[max(0,int(len(s)*0.95)-1)]

    def finalise(self):
        def t(key,floor): return max(floor, self._p95(self._s[key])*THRESHOLD_MULTIPLIER)
        self.thr_total=t("total",TOTAL_FLOOR);  self.thr_syn=t("syn",SYN_FLOOR)
        self.thr_udp=t("udp",UDP_FLOOR);        self.thr_icmp=t("icmp",ICMP_FLOOR)
        self.thr_auth_fail=t("auth_fail",AUTH_FAIL_FLOOR)
        self.thr_sudo=t("sudo",SUDO_EVENT_FLOOR)
        self.thr_proc=t("proc",PROCESS_SPAWN_FLOOR)
        log.info("Baseline finalised — net syn=%.0f udp=%.0f icmp=%.0f total=%.0f | "
                 "host auth=%.0f sudo=%.0f proc=%.0f",
                 self.thr_syn,self.thr_udp,self.thr_icmp,self.thr_total,
                 self.thr_auth_fail,self.thr_sudo,self.thr_proc)
        write_alert("INFO","engine",
            f"DETECTION active — syn={self.thr_syn:.0f} udp={self.thr_udp:.0f} "
            f"icmp={self.thr_icmp:.0f} auth={self.thr_auth_fail:.0f} "
            f"sudo={self.thr_sudo:.0f} proc={self.thr_proc:.0f}")

# =============================================================================
# RULE ENGINE
# =============================================================================

class RuleEngine:
    def __init__(self,bl:Baseline):
        self._b=bl
        self._streak:Dict[str,int]=collections.defaultdict(int)
        self._last_alert:Dict[str,float]=collections.defaultdict(float)

    def _fire(self,rule:str,level:str,detail:str,confirm:int=CONFIRM_WINDOWS):
        self._streak[rule]+=1
        if self._streak[rule]<confirm:
            log.debug("[SUSPECT] %s streak=%d/%d",rule,self._streak[rule],confirm); return
        now=time.monotonic()
        wait=COOLDOWN_SECS-(now-self._last_alert[rule])
        if wait>0: log.debug("[COOLDOWN] %s %.0fs",rule,wait); return
        self._last_alert[rule]=now; self._streak[rule]=0
        write_alert(level,rule,detail)

    def _fire_now(self,rule,level,detail): self._fire(rule,level,detail,confirm=1)
    def _clear(self,rule):
        if self._streak.get(rule): self._streak[rule]=0

    def evaluate(self,ns:NetStats,af:int,sd:int,pr:int,fim:List[Tuple[str,str]]):
        b=self._b
        # H1 Brute-force
        if af>b.thr_auth_fail:
            self._fire_now("brute_force",rate_to_level(af,AUTH_FAIL_FLOOR),
                f"failures={af} thr={b.thr_auth_fail:.0f} window={WINDOW_SECONDS}s")
        else: self._clear("brute_force")
        # H2 Priv escalation
        if sd>b.thr_sudo:
            lvl="CRITICAL" if sd>b.thr_sudo*3 else "HIGH"
            self._fire_now("priv_escalation",lvl,
                f"sudo_su_events={sd} thr={b.thr_sudo:.0f} window={WINDOW_SECONDS}s")
        else: self._clear("priv_escalation")
        # H3 Process anomaly
        if pr>b.thr_proc:
            self._fire_now("proc_anomaly",rate_to_level(pr,PROCESS_SPAWN_FLOOR),
                f"new_procs={pr} thr={b.thr_proc:.0f} window={WINDOW_SECONDS}s")
        else: self._clear("proc_anomaly")
        # H4 File integrity
        for _,detail in fim:
            write_alert("CRITICAL","file_integrity",detail)
        # N1 SYN flood
        if ns.syn_rate>b.thr_syn and ns.syn_ratio>SYN_RATIO_MIN:
            self._fire("syn_flood",rate_to_level(ns.syn_rate,SYN_FLOOR),
                f"syn={ns.syn_rate:.0f}/s thr={b.thr_syn:.0f} ratio={ns.syn_ratio*100:.0f}% pkts={ns.syn_count}")
        else: self._clear("syn_flood")
        # N2 UDP flood
        if ns.udp_rate>b.thr_udp:
            self._fire("udp_flood",rate_to_level(ns.udp_rate,UDP_FLOOR),
                f"udp={ns.udp_rate:.0f}/s thr={b.thr_udp:.0f} pkts={ns.udp_count}")
        else: self._clear("udp_flood")
        # N3 ICMP flood
        if ns.icmp_rate>b.thr_icmp:
            self._fire("icmp_flood",rate_to_level(ns.icmp_rate,ICMP_FLOOR),
                f"icmp={ns.icmp_rate:.0f}/s thr={b.thr_icmp:.0f} pkts={ns.icmp_count}")
        else: self._clear("icmp_flood")
        # N4 Port scan
        active:Set[str]=set()
        for ip,spread in ns.src_port_spread.items():
            if spread>=PORT_SCAN_THRESHOLD:
                key="scan_"+ip; active.add(key)
                lvl="HIGH" if spread>PORT_SCAN_THRESHOLD*4 else "MEDIUM"
                self._fire(key,lvl,f"src={ip} ports={spread} thr={PORT_SCAN_THRESHOLD}")
        for key in list(self._streak):
            if key.startswith("scan_") and key not in active: self._clear(key)
        log.debug("[WIN] syn=%.0f udp=%.0f icmp=%.0f | af=%d sd=%d pr=%d fim=%d",
                  ns.syn_rate,ns.udp_rate,ns.icmp_rate,af,sd,pr,len(fim))

# =============================================================================
# AUTH POLLER  (polls auth log 4× per second for fast detection)
# =============================================================================

class AuthPoller(threading.Thread):
    def __init__(self,mon:AuthLogMonitor):
        super().__init__(daemon=True,name="auth_poller")
        self._mon=mon; self._stop=threading.Event()
    def run(self):
        while not self._stop.is_set():
            self._mon.poll(); self._stop.wait(0.25)
    def stop(self): self._stop.set()

# =============================================================================
# SHARED STATE  (read by app.py)
# =============================================================================

hids_state:Dict = {
    "phase":        "stopped",
    "baseline_pct": 0.0,
    "uptime_start": None,
    "windows":      0,
    "last_ns":      None,
    "monitors":     {"auth_log":False,"psutil":False,"fim_files":0,"iface":"—"},
}
_state_lock=threading.Lock()

def _set_state(**kw):
    with _state_lock: hids_state.update(kw)

def get_state() -> Dict:
    with _state_lock: return dict(hids_state)

# =============================================================================
# ENGINE THREAD
# =============================================================================

class HIDSEngine(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True,name="hids_engine")
        self._stop_event=threading.Event()

    def stop(self): self._stop_event.set()

    def run(self):
        log.info("═"*60)
        log.info("Ulinzi HIDS engine starting")
        log.info("═"*60)

        iface=get_interface()
        buf=PacketBuffer()
        sniffer=Sniffer(buf,iface)
        auth_mon=AuthLogMonitor()
        auth_poll=AuthPoller(auth_mon)
        proc_mon=ProcessMonitor()
        fim=FileIntegrityMonitor()

        _set_state(phase="baseline",baseline_pct=0.0,uptime_start=datetime.now(),
                   monitors={"auth_log":auth_mon.available(),"psutil":proc_mon.available(),
                              "fim_files":len(fim._hashes),"iface":iface})

        sniffer.start(); auth_poll.start()

        write_alert("INFO","engine",
            f"HIDS started iface={iface} auth={'yes' if auth_mon.available() else 'no'} "
            f"psutil={'yes' if proc_mon.available() else 'no'} "
            f"fim={len(fim._hashes)} baseline={BASELINE_SECONDS}s window={WINDOW_SECONDS}s")

        bl=Baseline(); phase_start=time.monotonic()
        engine:Optional[RuleEngine]=None; windows=0

        log.info("BASELINE phase — %d seconds. Do NOT attack yet.", BASELINE_SECONDS)

        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(WINDOW_SECONDS)
                if self._stop_event.is_set(): break

                pkts=buf.drain()
                ns=compute_net_stats(pkts,WINDOW_SECONDS)
                af,sd=auth_mon.drain()
                pr=proc_mon.count_new()
                fim_alerts=fim.drain()
                windows+=1; elapsed=time.monotonic()-phase_start
                _set_state(windows=windows,last_ns=ns)

                if hids_state["phase"]=="baseline":
                    bl.record(ns,af,sd,pr)
                    pct=min(elapsed/BASELINE_SECONDS,0.99)
                    _set_state(baseline_pct=pct)
                    log.info("[BASELINE %.0f%%] pkts=%d syn=%.0f udp=%.0f icmp=%.0f af=%d sd=%d pr=%d",
                             pct*100,len(pkts),ns.syn_rate,ns.udp_rate,ns.icmp_rate,af,sd,pr)
                    if elapsed>=BASELINE_SECONDS:
                        bl.finalise(); engine=RuleEngine(bl)
                        _set_state(phase="detecting",baseline_pct=1.0)
                        log.info("DETECTION phase armed.")
                else:
                    log.info("[DETECTING] pkts=%d syn=%.0f udp=%.0f icmp=%.0f af=%d sd=%d pr=%d fim=%d",
                             len(pkts),ns.syn_rate,ns.udp_rate,ns.icmp_rate,af,sd,pr,len(fim_alerts))
                    engine.evaluate(ns,af,sd,pr,fim_alerts)
        finally:
            sniffer.stop(); auth_poll.stop(); fim.stop()
            _set_state(phase="stopped")
            log.info("Engine stopped after %d windows.", windows)
            write_alert("INFO","engine",f"HIDS stopped windows={windows}")

# =============================================================================
# PUBLIC API (used by app.py)
# =============================================================================

_engine_ref:Optional[HIDSEngine]=None

def start_engine() -> HIDSEngine:
    global _engine_ref
    if _engine_ref and _engine_ref.is_alive(): return _engine_ref
    _engine_ref=HIDSEngine(); _engine_ref.start(); return _engine_ref

def stop_engine():
    global _engine_ref
    if _engine_ref: _engine_ref.stop(); _engine_ref.join(timeout=5); _engine_ref=None

def is_running() -> bool:
    return _engine_ref is not None and _engine_ref.is_alive()

# =============================================================================
# HEADLESS ENTRY POINT
# =============================================================================

if __name__=="__main__":
    def _sig(*_): stop_engine()
    signal.signal(signal.SIGTERM,_sig); signal.signal(signal.SIGINT,_sig)
    eng=start_engine()
    try: eng.join()
    except KeyboardInterrupt: stop_engine()
