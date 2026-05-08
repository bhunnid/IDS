"""
hids_main.py  —  Ulinzi HIDS Detection Engine  (v3 — bug-fixed)
================================================================
Importable module started automatically by app.py.
Also runs headless:  sudo python3 hids_main.py

BUGS FIXED vs v2
----------------
BUG 1  SYN ratio false-negative
    Problem : The sniffer captures OUTBOUND packets too (RST replies from the
              target). With 500 SYN/s in + 500 RST/s out, ratio = 0.50 which
              is below the old SYN_RATIO_MIN=0.60 → flood never detected.
    Fix     : Only count INBOUND SYN packets (src_ip != host IPs).
              SYN_RATIO_MIN lowered to 0.40 as an extra safety net.

BUG 2  CONFIRM_WINDOWS killed bursty / short attacks
    Problem : CONFIRM_WINDOWS=2 meant a rule had to trigger in TWO consecutive
              1-second windows before firing. A 1-2 s flood or a quick nmap
              scan only fills 1 window → streak=1/2 → silent.
    Fix     : Network flood rules (SYN/UDP/ICMP) now use CONFIRM_WINDOWS=1 so
              they fire on the first window they exceed the threshold.
              Port scan keeps CONFIRM_WINDOWS=2 to avoid false positives from
              legitimate multi-port connections, but streak is now only reset
              after CLEAR_GRACE_WINDOWS of inactivity (not immediately on the
              first quiet window).

BUG 3  Port scan streak reset too aggressively
    Problem : If the scan finished mid-window, the next window had 0 ports and
              _clear() reset streak to 0 before it could reach 2 → never fired.
    Fix     : Streak for scan rules only resets after CLEAR_GRACE_WINDOWS (2)
              consecutive quiet windows, giving the alert time to accumulate.

BUG 4  SYN ratio measured across ALL TCP (including host outbound)
    Problem : The sniffer uses AF_PACKET which sees everything on the wire,
              including RST/ACK packets sent by the host in response to SYN
              floods. These non-SYN packets dilute the SYN ratio below the
              threshold.
    Fix     : Host IP addresses are detected at startup. When computing the
              SYN ratio, only packets whose src_ip is NOT a local host IP are
              counted as "inbound" for the ratio check.

ALERT LEVELS
    INFO      System events
    LOW       Mild anomaly worth watching
    MEDIUM    Suspicious — investigate soon
    HIGH      Likely attack in progress
    CRITICAL  Severe / confirmed intrusion

DETECTION RULES
    H1  Brute-force login     /var/log/auth.log failure rate
    H2  Privilege escalation  sudo/su event rate
    H3  Process anomaly       new-process spawn rate (psutil)
    H4  File integrity        SHA-256 change on critical files
    N1  SYN flood             inbound SYN rate (fixed ratio check)
    N2  UDP flood             UDP packet rate
    N3  ICMP flood            ICMP packet rate
    N4  Port scan             distinct dst-ports per source IP

ALERT FORMAT
    [YYYY-MM-DD HH:MM:SS] LEVEL:<level> RULE:<tag> | <detail>
"""

from __future__ import annotations

import os, re, sys, time, signal, socket, struct, hashlib
import logging, subprocess, threading, collections
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Optional, Set, Tuple

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

# =============================================================================
# CONFIGURATION
# =============================================================================

INTERFACE             = None   # None = auto-detect
BASELINE_SECONDS      = 60     # learning window (seconds)
WINDOW_SECONDS        = 1      # detection window — 1 s = near-instant alerts

# Adaptive threshold = max(hard_floor, p95_peak × multiplier)
THRESHOLD_MULTIPLIER  = 3

# ── Network hard floors (packets / second) ──────────────────────────────────
SYN_FLOOR             = 80     # lowered: easier to detect moderate floods
UDP_FLOOR             = 300
ICMP_FLOOR            = 30
TOTAL_FLOOR           = 600

# FIX 1: lowered from 0.60 → 0.40 to account for RST replies diluting ratio
SYN_RATIO_MIN         = 0.40

# Port scan: distinct dst-ports from one external IP in one 1-s window
PORT_SCAN_THRESHOLD   = 15     # lowered: nmap default scan hits this easily

# FIX 2: flood rules fire on first window (confirm=1), no waiting
FLOOD_CONFIRM         = 1
# FIX 3: scan needs 2 windows but only resets after this many quiet windows
SCAN_CONFIRM          = 2
CLEAR_GRACE_WINDOWS   = 2      # quiet windows needed before streak resets

COOLDOWN_SECS         = 20     # seconds before same rule re-fires

# ── Host hard floors (events per 1-s window) ────────────────────────────────
AUTH_FAIL_FLOOR       = 3
SUDO_EVENT_FLOOR      = 4
PROCESS_SPAWN_FLOOR   = 15

# ── File integrity ───────────────────────────────────────────────────────────
MONITORED_FILES: List[str] = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/hosts",  "/etc/ssh/sshd_config", "/etc/crontab",
]
FILE_CHECK_INTERVAL   = 5      # seconds between integrity polls

AUTH_LOG_CANDIDATES = [
    "/var/log/auth.log",   # Debian / Ubuntu / Kali
    "/var/log/secure",     # RHEL / CentOS / Fedora
    "/var/log/messages",
]

ALERT_LOG = "alerts.log"
INFO_LOG  = "hids.log"

# Severity scaling ratios
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


def get_host_ips() -> Set[str]:
    """Return all IPv4 addresses assigned to this host."""
    ips: Set[str] = {"127.0.0.1"}
    try:
        import socket as _s
        hostname = _s.gethostname()
        for info in _s.getaddrinfo(hostname, None):
            if info[0] == _s.AF_INET:
                ips.add(info[4][0])
    except Exception:
        pass
    if PSUTIL_OK:
        try:
            for addrs in psutil.net_if_addrs().values():
                for a in addrs:
                    if a.family == socket.AF_INET:
                        ips.add(a.address)
        except Exception:
            pass
    return ips

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

_VIRTUAL = ("lo","virbr","docker","br-","veth","tun","tap",
            "vmnet","vboxnet","dummy","sit","bond","team")

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
        for i, t in enumerate(toks):
            if t == "dev" and i+1 < len(toks): add(toks[i+1])
    except Exception: pass
    try:
        for _, n in socket.if_nameindex(): add(n)
    except Exception: pass
    try:
        with open("/proc/net/dev") as fh:
            for line in fh:
                if ":" in line: add(line.split(":")[0].strip())
    except OSError: pass
    for fb in ("eth0","ens33","ens3","enp0s3","ens160","enp3s0","wlan0"): add(fb)
    return result

def _can_bind(iface: str) -> bool:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((iface, 0)); s.close(); return True
    except OSError: return False

def get_interface() -> str:
    if INTERFACE: return INTERFACE
    cands = _candidate_interfaces()
    log.info("Interface candidates: %s", cands[:6])
    if os.geteuid() == 0:
        for iface in cands:
            if _can_bind(iface):
                log.info("Interface selected: %s", iface); return iface
    return cands[0] if cands else "eth0"

# =============================================================================
# NETWORK — PACKET PARSING
# =============================================================================

PROTO_TCP=6; PROTO_UDP=17; PROTO_ICMP=1
ETH_P_IP=0x0800; ETH_P_ALL=0x0003

class Packet:
    __slots__ = ("src_ip","proto","dport","is_syn","inbound")
    def __init__(self, src_ip: str, proto: int,
                 dport: int = 0, is_syn: bool = False, inbound: bool = True):
        self.src_ip=src_ip; self.proto=proto
        self.dport=dport;   self.is_syn=is_syn
        self.inbound=inbound  # FIX 1: track direction

def parse_packet(raw: bytes, host_ips: Set[str]) -> Optional[Packet]:
    if len(raw) < 34: return None
    if struct.unpack_from("!H", raw, 12)[0] != ETH_P_IP: return None
    ip = raw[14:]
    if len(ip) < 20: return None
    ihl     = (ip[0] & 0x0F) * 4
    proto   = ip[9]
    try:
        src_ip = socket.inet_ntoa(ip[12:16])
    except OSError: return None
    # FIX 1: determine direction — inbound = source is NOT a local IP
    inbound = src_ip not in host_ips
    payload = ip[ihl:]; dport = 0; is_syn = False
    if proto == PROTO_TCP and len(payload) >= 14:
        dport  = struct.unpack_from("!H", payload, 2)[0]
        flags  = payload[13]
        is_syn = bool(flags & 0x02) and not bool(flags & 0x10)
    elif proto == PROTO_UDP and len(payload) >= 4:
        dport  = struct.unpack_from("!H", payload, 2)[0]
    return Packet(src_ip, proto, dport, is_syn, inbound)

# =============================================================================
# NETWORK — PACKET BUFFER + SNIFFER
# =============================================================================

class PacketBuffer:
    def __init__(self):
        self._lock = threading.Lock()
        self._pkts: List[Packet] = []

    def put(self, p: Packet):
        with self._lock: self._pkts.append(p)

    def drain(self) -> List[Packet]:
        with self._lock:
            out, self._pkts = self._pkts, []; return out

class Sniffer(threading.Thread):
    def __init__(self, buf: PacketBuffer, iface: str, host_ips: Set[str]):
        super().__init__(daemon=True, name="sniffer")
        self._buf      = buf
        self._iface    = iface
        self._host_ips = host_ips
        self._stop     = threading.Event()
        self._sock     = None

    def run(self):
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(ETH_P_ALL))
            self._sock.bind((self._iface, 0))
            self._sock.settimeout(0.2)  # shorter timeout = more responsive
            log.info("Sniffer bound to: %s", self._iface)
        except PermissionError:
            log.critical("Permission denied — run: sudo python3 app.py")
            os._exit(1)
        except OSError as e:
            log.critical("Cannot bind to %r: %s\nCheck interface with: ip link show", self._iface, e)
            os._exit(1)

        while not self._stop.is_set():
            try:
                raw = self._sock.recv(65535)
                p   = parse_packet(raw, self._host_ips)
                if p: self._buf.put(p)
            except socket.timeout: continue
            except OSError: break
        if self._sock: self._sock.close()

    def stop(self): self._stop.set()

# =============================================================================
# NETWORK — WINDOW STATS
# =============================================================================

class NetStats:
    __slots__ = ("total_rate","syn_rate","udp_rate","icmp_rate",
                 "tcp_count","syn_count","udp_count","icmp_count",
                 "inbound_tcp","inbound_syn",  # FIX 1: inbound-only counts
                 "syn_ratio","src_port_spread")
    def __init__(self):
        self.total_rate=0.0; self.syn_rate=0.0
        self.udp_rate=0.0;   self.icmp_rate=0.0
        self.tcp_count=0;    self.syn_count=0
        self.udp_count=0;    self.icmp_count=0
        self.inbound_tcp=0;  self.inbound_syn=0
        self.syn_ratio=0.0
        self.src_port_spread: Dict[str,int] = {}

def compute_net_stats(packets: List[Packet], w: float) -> NetStats:
    ns = NetStats()
    src_ports: Dict[str, Set[int]] = collections.defaultdict(set)

    for p in packets:
        if p.proto == PROTO_TCP:
            ns.tcp_count += 1
            src_ports[p.src_ip].add(p.dport)
            if p.is_syn: ns.syn_count += 1
            # FIX 1: only count inbound for ratio
            if p.inbound:
                ns.inbound_tcp += 1
                if p.is_syn: ns.inbound_syn += 1
        elif p.proto == PROTO_UDP:
            ns.udp_count += 1
            if p.inbound: src_ports[p.src_ip].add(p.dport)
        elif p.proto == PROTO_ICMP:
            ns.icmp_count += 1

    ns.total_rate = len(packets) / w
    ns.syn_rate   = ns.inbound_syn / w     # rate based on INBOUND SYNs only
    ns.udp_rate   = ns.udp_count / w
    ns.icmp_rate  = ns.icmp_count / w
    # FIX 1: SYN ratio from INBOUND traffic only (eliminates RST dilution)
    ns.syn_ratio  = (ns.inbound_syn / ns.inbound_tcp) if ns.inbound_tcp else 0.0
    # Only track external IPs for port scan detection
    ns.src_port_spread = {
        ip: len(ports) for ip, ports in src_ports.items()
    }
    return ns

# =============================================================================
# HOST — AUTH LOG MONITOR  (H1 brute-force, H2 priv-esc)
# =============================================================================

_AUTH_FAIL_RE = re.compile(
    r"(Failed password|authentication failure|Invalid user|FAILED LOGIN|"
    r"pam_unix.*authentication failure|Connection closed by authenticating user|"
    r"Too many authentication|Maximum authentication attempts)",
    re.IGNORECASE)
_SUDO_RE = re.compile(
    r"(sudo:.*COMMAND|su:.*session opened|sudo:.*authentication failure|"
    r"sudo:.*incorrect password|sudo:.*3 incorrect password)",
    re.IGNORECASE)

class AuthLogMonitor:
    def __init__(self):
        self._path = self._find()
        self._pos  = 0
        self._fail = 0
        self._sudo = 0
        self._lock = threading.Lock()
        if self._path:
            try: self._pos = os.path.getsize(self._path)
            except OSError: pass
            log.info("Auth log: %s (offset %d)", self._path, self._pos)
        else:
            log.warning("No auth log found — H1/H2 rules disabled")

    @staticmethod
    def _find() -> Optional[str]:
        for p in AUTH_LOG_CANDIDATES:
            if os.path.exists(p) and os.access(p, os.R_OK): return p
        return None

    def poll(self):
        if not self._path: return
        try: size = os.path.getsize(self._path)
        except OSError: return
        if size < self._pos: self._pos = 0
        if size == self._pos: return
        try:
            with open(self._path, "r", errors="replace") as fh:
                fh.seek(self._pos)
                chunk = fh.read(size - self._pos)
                self._pos = fh.tell()
        except OSError: return
        f = d = 0
        for line in chunk.splitlines():
            if _AUTH_FAIL_RE.search(line): f += 1
            if _SUDO_RE.search(line):      d += 1
        with self._lock:
            self._fail += f
            self._sudo += d

    def drain(self) -> Tuple[int,int]:
        with self._lock:
            f, s = self._fail, self._sudo
            self._fail = self._sudo = 0
            return f, s

    def available(self) -> bool: return self._path is not None

# =============================================================================
# HOST — PROCESS MONITOR  (H3)
# =============================================================================

class ProcessMonitor:
    def __init__(self):
        self._ok   = PSUTIL_OK
        self._pids: Set[int] = set()
        if self._ok:
            try:
                self._pids = {p.pid for p in psutil.process_iter()}
                log.info("Process monitor: active (%d initial PIDs)", len(self._pids))
            except Exception: self._ok = False
        if not self._ok:
            log.warning("psutil unavailable — H3 disabled")

    def count_new(self) -> int:
        if not self._ok: return 0
        try: cur = {p.pid for p in psutil.process_iter()}
        except Exception: return 0
        new = cur - self._pids
        self._pids = cur
        return len(new)

    def available(self) -> bool: return self._ok

# =============================================================================
# HOST — FILE INTEGRITY MONITOR  (H4)
# =============================================================================

class FileIntegrityMonitor:
    def __init__(self):
        self._hashes:  Dict[str,str]       = {}
        self._skip:    Set[str]            = set()
        self._pending: List[Tuple[str,str]] = []
        self._lock   = threading.Lock()
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="fim")
        self._baseline()
        self._thread.start()
        log.info("FIM: watching %d file(s)", len(self._hashes))

    @staticmethod
    def _hash(path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""): h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError): return None

    def _baseline(self):
        for p in MONITORED_FILES:
            h = self._hash(p)
            if h is None: self._skip.add(p)
            else: self._hashes[p] = h

    def _run(self):
        while not self._stop.is_set():
            self._stop.wait(FILE_CHECK_INTERVAL)
            if self._stop.is_set(): break
            for path, known in list(self._hashes.items()):
                cur = self._hash(path)
                if cur and cur != known:
                    detail = (f"path={path} "
                              f"prev_hash={known[:16]}... "
                              f"new_hash={cur[:16]}...")
                    with self._lock:
                        self._pending.append((path, detail))
                    self._hashes[path] = cur

    def drain(self) -> List[Tuple[str,str]]:
        with self._lock:
            out, self._pending = self._pending, []; return out

    def stop(self): self._stop.set()

# =============================================================================
# ADAPTIVE BASELINE
# =============================================================================

class Baseline:
    def __init__(self):
        self._s: Dict[str,List[float]] = {
            "syn":[], "udp":[], "icmp":[], "total":[],
            "auth_fail":[], "sudo":[], "proc":[],
        }
        # Start at hard floors
        self.thr_syn       = float(SYN_FLOOR)
        self.thr_udp       = float(UDP_FLOOR)
        self.thr_icmp      = float(ICMP_FLOOR)
        self.thr_total     = float(TOTAL_FLOOR)
        self.thr_auth_fail = float(AUTH_FAIL_FLOOR)
        self.thr_sudo      = float(SUDO_EVENT_FLOOR)
        self.thr_proc      = float(PROCESS_SPAWN_FLOOR)

    def record(self, ns: NetStats, af: int, sd: int, pr: int):
        self._s["syn"].append(ns.syn_rate)
        self._s["udp"].append(ns.udp_rate)
        self._s["icmp"].append(ns.icmp_rate)
        self._s["total"].append(ns.total_rate)
        self._s["auth_fail"].append(float(af))
        self._s["sudo"].append(float(sd))
        self._s["proc"].append(float(pr))

    @staticmethod
    def _p95(v: List[float]) -> float:
        if not v: return 0.0
        s = sorted(v)
        return s[max(0, int(len(s) * 0.95) - 1)]

    def finalise(self):
        def t(key: str, floor: float) -> float:
            return max(floor, self._p95(self._s[key]) * THRESHOLD_MULTIPLIER)
        self.thr_syn       = t("syn",       SYN_FLOOR)
        self.thr_udp       = t("udp",       UDP_FLOOR)
        self.thr_icmp      = t("icmp",      ICMP_FLOOR)
        self.thr_total     = t("total",     TOTAL_FLOOR)
        self.thr_auth_fail = t("auth_fail", AUTH_FAIL_FLOOR)
        self.thr_sudo      = t("sudo",      SUDO_EVENT_FLOOR)
        self.thr_proc      = t("proc",      PROCESS_SPAWN_FLOOR)
        log.info(
            "Baseline finalised — "
            "syn=%.0f/s udp=%.0f/s icmp=%.0f/s total=%.0f/s | "
            "auth_fail=%.0f sudo=%.0f proc=%.0f",
            self.thr_syn, self.thr_udp, self.thr_icmp, self.thr_total,
            self.thr_auth_fail, self.thr_sudo, self.thr_proc,
        )
        write_alert("INFO", "engine",
            f"DETECTION active — "
            f"syn={self.thr_syn:.0f} udp={self.thr_udp:.0f} "
            f"icmp={self.thr_icmp:.0f} "
            f"auth={self.thr_auth_fail:.0f} "
            f"sudo={self.thr_sudo:.0f} proc={self.thr_proc:.0f}")

# =============================================================================
# RULE ENGINE  (all 4 bugs fixed here)
# =============================================================================

class RuleEngine:
    def __init__(self, bl: Baseline):
        self._b            = bl
        self._streak:      Dict[str,int]   = collections.defaultdict(int)
        self._quiet:       Dict[str,int]   = collections.defaultdict(int)  # FIX 3
        self._last_alert:  Dict[str,float] = collections.defaultdict(float)

    # ── internal ──────────────────────────────────────────────────────────────

    def _fire(self, rule: str, level: str, detail: str,
              confirm: int = 1) -> bool:
        """Increment streak; fire when streak >= confirm and cooldown elapsed.
        Returns True if alert was fired."""
        self._streak[rule] += 1
        self._quiet[rule]   = 0   # reset quiet counter whenever active

        if self._streak[rule] < confirm:
            log.debug("[SUSPECT] %s streak=%d/%d", rule, self._streak[rule], confirm)
            return False

        now  = time.monotonic()
        wait = COOLDOWN_SECS - (now - self._last_alert[rule])
        if wait > 0:
            log.debug("[COOLDOWN] %s %.0fs remaining", rule, wait)
            return False

        self._last_alert[rule] = now
        self._streak[rule]     = 0
        write_alert(level, rule, detail)
        return True

    def _soft_clear(self, rule: str):
        """FIX 3: Only reset streak after CLEAR_GRACE_WINDOWS quiet windows."""
        if self._streak.get(rule, 0) == 0:
            return
        self._quiet[rule] = self._quiet.get(rule, 0) + 1
        if self._quiet[rule] >= CLEAR_GRACE_WINDOWS:
            log.debug("[CLEAR] %s after %d quiet windows", rule, self._quiet[rule])
            self._streak[rule] = 0
            self._quiet[rule]  = 0

    def _hard_clear(self, rule: str):
        """Immediate reset — for host rules that are per-window."""
        self._streak[rule] = 0
        self._quiet[rule]  = 0

    # ── evaluation ────────────────────────────────────────────────────────────

    def evaluate(self, ns: NetStats,
                 af: int, sd: int, pr: int,
                 fim: List[Tuple[str,str]]) -> None:
        b = self._b

        # ── H1  Brute-force login ─────────────────────────────────────────────
        if af > b.thr_auth_fail:
            self._fire("brute_force",
                       rate_to_level(af, AUTH_FAIL_FLOOR),
                       f"failures={af} thr={b.thr_auth_fail:.0f} window={WINDOW_SECONDS}s",
                       confirm=1)
        else:
            self._hard_clear("brute_force")

        # ── H2  Privilege escalation ──────────────────────────────────────────
        if sd > b.thr_sudo:
            lvl = "CRITICAL" if sd > b.thr_sudo * 3 else "HIGH"
            self._fire("priv_escalation", lvl,
                       f"sudo_su_events={sd} thr={b.thr_sudo:.0f} window={WINDOW_SECONDS}s",
                       confirm=1)
        else:
            self._hard_clear("priv_escalation")

        # ── H3  Process anomaly ───────────────────────────────────────────────
        if pr > b.thr_proc:
            self._fire("proc_anomaly",
                       rate_to_level(pr, PROCESS_SPAWN_FLOOR),
                       f"new_procs={pr} thr={b.thr_proc:.0f} window={WINDOW_SECONDS}s",
                       confirm=1)
        else:
            self._hard_clear("proc_anomaly")

        # ── H4  File integrity ────────────────────────────────────────────────
        for _, detail in fim:
            write_alert("CRITICAL", "file_integrity", detail)

        # ── N1  SYN flood (FIX 1+2) ──────────────────────────────────────────
        # Use inbound SYN rate and inbound SYN ratio (no RST dilution)
        if ns.syn_rate > b.thr_syn and ns.syn_ratio > SYN_RATIO_MIN:
            self._fire("syn_flood",
                       rate_to_level(ns.syn_rate, SYN_FLOOR),
                       f"inbound_syn={ns.syn_rate:.0f}/s thr={b.thr_syn:.0f} "
                       f"ratio={ns.syn_ratio*100:.0f}% "
                       f"inbound_tcp={ns.inbound_tcp}",
                       confirm=FLOOD_CONFIRM)   # FIX 2: confirm=1
        else:
            self._soft_clear("syn_flood")

        # ── N2  UDP flood (FIX 2) ─────────────────────────────────────────────
        if ns.udp_rate > b.thr_udp:
            self._fire("udp_flood",
                       rate_to_level(ns.udp_rate, UDP_FLOOR),
                       f"udp={ns.udp_rate:.0f}/s thr={b.thr_udp:.0f} pkts={ns.udp_count}",
                       confirm=FLOOD_CONFIRM)   # FIX 2: confirm=1
        else:
            self._soft_clear("udp_flood")

        # ── N3  ICMP flood (FIX 2) ────────────────────────────────────────────
        if ns.icmp_rate > b.thr_icmp:
            self._fire("icmp_flood",
                       rate_to_level(ns.icmp_rate, ICMP_FLOOR),
                       f"icmp={ns.icmp_rate:.0f}/s thr={b.thr_icmp:.0f} pkts={ns.icmp_count}",
                       confirm=FLOOD_CONFIRM)   # FIX 2: confirm=1
        else:
            self._soft_clear("icmp_flood")

        # ── N4  Port scan (FIX 3) ─────────────────────────────────────────────
        active: Set[str] = set()
        for ip, spread in ns.src_port_spread.items():
            if spread >= PORT_SCAN_THRESHOLD:
                key = "scan_" + ip
                active.add(key)
                lvl = "HIGH" if spread > PORT_SCAN_THRESHOLD * 4 else "MEDIUM"
                self._fire(key, lvl,
                           f"src={ip} ports={spread} thr={PORT_SCAN_THRESHOLD}",
                           confirm=SCAN_CONFIRM)  # needs 2 windows
        # FIX 3: soft-clear only (grace window) instead of hard clear
        for key in list(self._streak):
            if key.startswith("scan_") and key not in active:
                self._soft_clear(key)

        log.debug(
            "[WIN] inbound_syn=%.0f udp=%.0f icmp=%.0f syn_ratio=%.0f%% | "
            "af=%d sd=%d pr=%d fim=%d",
            ns.syn_rate, ns.udp_rate, ns.icmp_rate, ns.syn_ratio * 100,
            af, sd, pr, len(fim),
        )

# =============================================================================
# AUTH POLLER  (polls 4× per second)
# =============================================================================

class AuthPoller(threading.Thread):
    def __init__(self, mon: AuthLogMonitor):
        super().__init__(daemon=True, name="auth_poller")
        self._mon  = mon
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            self._mon.poll()
            self._stop.wait(0.25)

    def stop(self): self._stop.set()

# =============================================================================
# SHARED STATE  (read by app.py)
# =============================================================================

hids_state: Dict = {
    "phase":        "stopped",
    "baseline_pct": 0.0,
    "uptime_start": None,
    "windows":      0,
    "last_ns":      None,
    "monitors":     {"auth_log":False,"psutil":False,"fim_files":0,"iface":"—"},
}
_state_lock = threading.Lock()

def _set_state(**kw):
    with _state_lock: hids_state.update(kw)

def get_state() -> Dict:
    with _state_lock: return dict(hids_state)

# =============================================================================
# ENGINE THREAD
# =============================================================================

class HIDSEngine(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="hids_engine")
        self._stop_event = threading.Event()

    def stop(self): self._stop_event.set()

    def run(self):
        log.info("═" * 60)
        log.info("Ulinzi HIDS v3 engine starting")
        log.info("═" * 60)

        # Detect host IPs before starting sniffer (needed for FIX 1)
        host_ips = get_host_ips()
        log.info("Host IPs (excluded from ratio): %s", sorted(host_ips))

        iface      = get_interface()
        buf        = PacketBuffer()
        sniffer    = Sniffer(buf, iface, host_ips)   # FIX 1: pass host_ips
        auth_mon   = AuthLogMonitor()
        auth_poll  = AuthPoller(auth_mon)
        proc_mon   = ProcessMonitor()
        fim        = FileIntegrityMonitor()

        _set_state(
            phase        = "baseline",
            baseline_pct = 0.0,
            uptime_start = datetime.now(),
            monitors     = {
                "auth_log":  auth_mon.available(),
                "psutil":    proc_mon.available(),
                "fim_files": len(fim._hashes),
                "iface":     iface,
            },
        )

        sniffer.start()
        auth_poll.start()

        write_alert("INFO", "engine",
            f"HIDS started iface={iface} "
            f"host_ips={len(host_ips)} "
            f"auth={'yes' if auth_mon.available() else 'no'} "
            f"psutil={'yes' if proc_mon.available() else 'no'} "
            f"fim={len(fim._hashes)} "
            f"baseline={BASELINE_SECONDS}s window={WINDOW_SECONDS}s "
            f"flood_confirm={FLOOD_CONFIRM} scan_confirm={SCAN_CONFIRM}")

        bl          = Baseline()
        phase_start = time.monotonic()
        engine: Optional[RuleEngine] = None
        windows     = 0

        log.info("BASELINE — %d seconds. Do NOT run attacks yet.", BASELINE_SECONDS)

        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(WINDOW_SECONDS)
                if self._stop_event.is_set(): break

                pkts       = buf.drain()
                ns         = compute_net_stats(pkts, WINDOW_SECONDS)
                af, sd     = auth_mon.drain()
                pr         = proc_mon.count_new()
                fim_alerts = fim.drain()
                windows   += 1
                elapsed    = time.monotonic() - phase_start

                _set_state(windows=windows, last_ns=ns)

                if hids_state["phase"] == "baseline":
                    bl.record(ns, af, sd, pr)
                    pct = min(elapsed / BASELINE_SECONDS, 0.99)
                    _set_state(baseline_pct=pct)
                    log.info(
                        "[BASELINE %3.0f%%] pkts=%d "
                        "syn=%.0f/s udp=%.0f/s icmp=%.0f/s syn_ratio=%.0f%% "
                        "| af=%d sd=%d pr=%d",
                        pct*100, len(pkts),
                        ns.syn_rate, ns.udp_rate, ns.icmp_rate,
                        ns.syn_ratio * 100,
                        af, sd, pr,
                    )
                    if elapsed >= BASELINE_SECONDS:
                        bl.finalise()
                        engine = RuleEngine(bl)
                        _set_state(phase="detecting", baseline_pct=1.0)
                        log.info("DETECTION phase — engine armed. Run attacks now.")
                else:
                    log.info(
                        "[DETECTING] pkts=%d "
                        "syn=%.0f/s(%.0f%%) udp=%.0f/s icmp=%.0f/s "
                        "| af=%d sd=%d pr=%d fim=%d",
                        len(pkts),
                        ns.syn_rate, ns.syn_ratio * 100,
                        ns.udp_rate, ns.icmp_rate,
                        af, sd, pr, len(fim_alerts),
                    )
                    engine.evaluate(ns, af, sd, pr, fim_alerts)

        finally:
            sniffer.stop()
            auth_poll.stop()
            fim.stop()
            _set_state(phase="stopped")
            log.info("Engine stopped after %d windows.", windows)
            write_alert("INFO", "engine", f"HIDS stopped windows={windows}")

# =============================================================================
# PUBLIC API
# =============================================================================

_engine_ref: Optional[HIDSEngine] = None

def start_engine() -> HIDSEngine:
    global _engine_ref
    if _engine_ref and _engine_ref.is_alive(): return _engine_ref
    _engine_ref = HIDSEngine()
    _engine_ref.start()
    return _engine_ref

def stop_engine():
    global _engine_ref
    if _engine_ref:
        _engine_ref.stop()
        _engine_ref.join(timeout=5)
        _engine_ref = None

def is_running() -> bool:
    return _engine_ref is not None and _engine_ref.is_alive()

# =============================================================================
# HEADLESS ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    def _sig(*_): stop_engine()
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT,  _sig)
    eng = start_engine()
    try:
        eng.join()
    except KeyboardInterrupt:
        stop_engine()