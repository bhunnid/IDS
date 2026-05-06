"""
hids_main.py  —  Ulinzi: Lightweight Host Intrusion Detection System (HIDS)
                 for Kali Linux / small network environments

HOW IT WORKS
------------
Phase 1  BASELINE  (60 seconds)
    The HIDS observes normal host activity across 3-second windows and
    computes p99 statistical baselines for all monitored metrics.
    Detection thresholds = max(hard_floor, p99_peak * THRESHOLD_MULTIPLIER).
    Do NOT run attacks during this phase.

Phase 2  DETECTION
    Seven rule groups evaluate every 3-second window.  An alert fires only when:
      - the metric exceeds the computed threshold, AND
      - the rule triggers for CONFIRM_WINDOWS consecutive windows (network rules), AND
      - the per-rule cooldown timer has elapsed.

    Host-Level Rules  (event-driven, no confirmation window):
      Brute-force      — auth failure rate exceeds threshold (from /var/log/auth.log)
      Privilege escal. — abnormal sudo/su usage rate
      Process anomaly  — abnormal process spawn rate (via psutil)
      File integrity   — SHA-256 mismatch on monitored critical files (inotify/polling)

    Network-Level Rules  (confirmation window applied):
      SYN flood        — syn_rate > threshold  AND  >70% of TCP are SYNs
      UDP flood        — udp_rate > threshold
      ICMP flood       — icmp_rate > threshold
      Port scan        — one source IP touches >= 50 distinct dst ports in 3 s

ALERT FORMAT  (appended to alerts.log)
    [YYYY-MM-DD HH:MM:SS] ALERT: <kind> | <detail>

ATTACK SIMULATION COMMANDS  (run in a second terminal)
    Brute-force login : hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
    Port scan         : sudo nmap -sS -p 1-1000 --min-rate 500 <target-ip>
    SYN flood         : sudo hping3 -S --flood -V -p 80 <target-ip>
    UDP flood         : sudo hping3 --udp --flood -p 53 <target-ip>
    ICMP flood        : sudo hping3 --icmp --flood <target-ip>
    File tamper       : echo "tampered" >> /etc/hosts   (restore: sudo git checkout /etc/hosts)
    Priv escalation   : sudo ls  (repeated rapidly to exceed sudo threshold)
"""

from __future__ import annotations

import os
import re
import sys
import time
import signal
import socket
import struct
import hashlib
import logging
import subprocess
import threading
import collections
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Optional, Dict, Set, List, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# OPTIONAL DEPENDENCY: psutil
# ─────────────────────────────────────────────────────────────────────────────
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# Network interface — leave None to auto-detect.
INTERFACE = None

BASELINE_SECONDS     = 60   # seconds to observe normal host activity
WINDOW_SECONDS       = 3    # measurement interval in seconds
THRESHOLD_MULTIPLIER = 4    # adaptive threshold = p99_peak * this value

# ── Network hard floors ───────────────────────────────────────────────────────
SYN_FLOOR   = 500    # SYN packets/s
UDP_FLOOR   = 2000   # UDP packets/s
ICMP_FLOOR  = 200    # ICMP packets/s
TOTAL_FLOOR = 3000   # total packets/s

SYN_RATIO_MIN       = 0.70  # fraction of TCP that must be SYNs for a flood
PORT_SCAN_THRESHOLD = 50    # distinct dst ports from one IP in one window
CONFIRM_WINDOWS     = 2     # consecutive windows before network alert fires
COOLDOWN_SECS       = 60    # seconds before same rule can fire again

# ── Host-level hard floors ────────────────────────────────────────────────────
AUTH_FAIL_FLOOR     = 5     # failed auth events per window to trigger alert
SUDO_EVENT_FLOOR    = 10    # sudo/su log events per window
PROCESS_SPAWN_FLOOR = 30    # new processes per window (psutil)

# ── File integrity monitoring ─────────────────────────────────────────────────
# Paths to monitor for unauthorised modification.
# Add or remove paths as appropriate for your environment.
MONITORED_FILES: List[str] = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
]
FILE_CHECK_INTERVAL = 15    # seconds between file integrity polls

# ── Log sources ───────────────────────────────────────────────────────────────
# Ordered list — first path that exists on this system is used.
AUTH_LOG_CANDIDATES = [
    "/var/log/auth.log",        # Debian/Ubuntu/Kali
    "/var/log/secure",          # RHEL/CentOS/Fedora
    "/var/log/messages",        # some distros
]

ALERT_LOG              = "alerts.log"
INFO_LOG               = "hids.log"
ZERO_TRAFFIC_WARN_AFTER = 5

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging() -> None:
    fmt  = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    fh = RotatingFileHandler(INFO_LOG, maxBytes=5_000_000, backupCount=2)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    root.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    root.addHandler(ch)


_setup_logging()
log = logging.getLogger("hids")


def write_alert(kind: str, detail: str) -> None:
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] ALERT: {kind} | {detail}"
    try:
        with open(ALERT_LOG, "a") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        log.error("Cannot write alert: %s", exc)
    log.warning(">>> ALERT: %s | %s", kind, detail)


# ─────────────────────────────────────────────────────────────────────────────
# NETWORK — INTERFACE DETECTION
# ─────────────────────────────────────────────────────────────────────────────

_VIRTUAL = ("lo", "virbr", "docker", "br-", "veth", "tun", "tap",
            "vmnet", "vboxnet", "dummy", "sit")


def _is_virtual(name: str) -> bool:
    return any(name.startswith(p) for p in _VIRTUAL)


def _candidate_interfaces() -> List[str]:
    seen:   Set[str]  = set()
    result: List[str] = []

    def add(name: str) -> None:
        name = name.strip()
        if name and name not in seen and not _is_virtual(name):
            seen.add(name)
            result.append(name)

    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            stderr=subprocess.DEVNULL, timeout=3,
        ).decode()
        tokens = out.split()
        for i, tok in enumerate(tokens):
            if tok == "dev" and i + 1 < len(tokens):
                add(tokens[i + 1])
    except Exception:
        pass

    try:
        for _, name in socket.if_nameindex():
            add(name)
    except Exception:
        pass

    try:
        with open("/proc/net/dev") as fh:
            for line in fh:
                if ":" in line:
                    add(line.split(":")[0].strip())
    except OSError:
        pass

    for fb in ("eth0", "ens33", "ens3", "enp0s3", "ens160", "wlan0"):
        add(fb)

    return result


def _can_bind(iface: str) -> bool:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((iface, 0))
        s.close()
        return True
    except OSError:
        return False


def get_interface() -> str:
    if INTERFACE:
        log.info("Interface (configured): %s", INTERFACE)
        return INTERFACE

    candidates = _candidate_interfaces()
    log.info("Interface candidates: %s", candidates[:8])

    if os.geteuid() == 0:
        for iface in candidates:
            if _can_bind(iface):
                log.info("Interface selected (bind OK): %s", iface)
                return iface
    else:
        log.info("Not root — selected: %s", candidates[0] if candidates else "eth0")

    return candidates[0] if candidates else "eth0"


# ─────────────────────────────────────────────────────────────────────────────
# NETWORK — PACKET PARSING
# ─────────────────────────────────────────────────────────────────────────────

PROTO_TCP  = 6
PROTO_UDP  = 17
PROTO_ICMP = 1
ETH_P_IP   = 0x0800
ETH_P_ALL  = 0x0003


class Packet:
    __slots__ = ("src_ip", "proto", "dport", "is_syn")

    def __init__(self, src_ip: str, proto: int,
                 dport: int = 0, is_syn: bool = False) -> None:
        self.src_ip = src_ip
        self.proto  = proto
        self.dport  = dport
        self.is_syn = is_syn


def parse_packet(raw: bytes) -> Optional[Packet]:
    if len(raw) < 34:
        return None
    if struct.unpack_from("!H", raw, 12)[0] != ETH_P_IP:
        return None
    ip = raw[14:]
    if len(ip) < 20:
        return None
    ihl   = (ip[0] & 0x0F) * 4
    proto = ip[9]
    try:
        src_ip = socket.inet_ntoa(ip[12:16])
    except OSError:
        return None
    payload = ip[ihl:]
    dport, is_syn = 0, False
    if proto == PROTO_TCP and len(payload) >= 14:
        dport  = struct.unpack_from("!H", payload, 2)[0]
        flags  = payload[13]
        is_syn = bool(flags & 0x02) and not bool(flags & 0x10)
    elif proto == PROTO_UDP and len(payload) >= 4:
        dport = struct.unpack_from("!H", payload, 2)[0]
    return Packet(src_ip, proto, dport, is_syn)


# ─────────────────────────────────────────────────────────────────────────────
# NETWORK — PACKET BUFFER & SNIFFER THREAD
# ─────────────────────────────────────────────────────────────────────────────

class PacketBuffer:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pkts: List[Packet] = []

    def put(self, pkt: Packet) -> None:
        with self._lock:
            self._pkts.append(pkt)

    def drain(self) -> List[Packet]:
        with self._lock:
            out, self._pkts = self._pkts, []
        return out


class Sniffer(threading.Thread):

    def __init__(self, buf: PacketBuffer, iface: str) -> None:
        super().__init__(daemon=True, name="sniffer")
        self._buf   = buf
        self._iface = iface
        self._stop  = threading.Event()
        self._sock: Optional[socket.socket] = None

    def run(self) -> None:
        try:
            self._sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL),
            )
            self._sock.bind((self._iface, 0))
            self._sock.settimeout(1.0)
            log.info("Sniffer bound to interface: %s", self._iface)
        except PermissionError:
            log.critical("Permission denied — run with:  sudo python3 hids_main.py")
            os._exit(1)
        except OSError as exc:
            log.critical(
                "Cannot bind to %r: %s\n"
                "  Check interfaces with:  ip link show\n"
                "  Then set INTERFACE = 'your_iface' at the top of hids_main.py",
                self._iface, exc,
            )
            os._exit(1)

        while not self._stop.is_set():
            try:
                raw = self._sock.recv(65535)
                pkt = parse_packet(raw)
                if pkt:
                    self._buf.put(pkt)
            except socket.timeout:
                continue
            except OSError:
                break

        if self._sock:
            self._sock.close()

    def stop(self) -> None:
        self._stop.set()


# ─────────────────────────────────────────────────────────────────────────────
# NETWORK — WINDOW STATISTICS
# ─────────────────────────────────────────────────────────────────────────────

class NetworkWindowStats:
    __slots__ = (
        "total_rate", "syn_rate",  "udp_rate",  "icmp_rate",
        "tcp_count",  "syn_count", "udp_count", "icmp_count",
        "syn_ratio",  "src_port_spread",
    )

    def __init__(self) -> None:
        self.total_rate = 0.0;  self.syn_rate  = 0.0
        self.udp_rate   = 0.0;  self.icmp_rate = 0.0
        self.tcp_count  = 0;    self.syn_count  = 0
        self.udp_count  = 0;    self.icmp_count = 0
        self.syn_ratio  = 0.0
        self.src_port_spread: Dict[str, int] = {}


def compute_network_stats(packets: List[Packet], window_secs: float) -> NetworkWindowStats:
    ws        = NetworkWindowStats()
    src_ports: Dict[str, Set[int]] = collections.defaultdict(set)

    for p in packets:
        if p.proto == PROTO_TCP:
            ws.tcp_count += 1
            src_ports[p.src_ip].add(p.dport)
            if p.is_syn:
                ws.syn_count += 1
        elif p.proto == PROTO_UDP:
            ws.udp_count += 1
            src_ports[p.src_ip].add(p.dport)
        elif p.proto == PROTO_ICMP:
            ws.icmp_count += 1

    w = window_secs
    ws.total_rate = len(packets)  / w
    ws.syn_rate   = ws.syn_count  / w
    ws.udp_rate   = ws.udp_count  / w
    ws.icmp_rate  = ws.icmp_count / w
    ws.syn_ratio  = (ws.syn_count / ws.tcp_count) if ws.tcp_count else 0.0
    ws.src_port_spread = {ip: len(ports) for ip, ports in src_ports.items()}
    return ws


# ─────────────────────────────────────────────────────────────────────────────
# HOST — AUTH LOG MONITOR
# Detects: brute-force login attempts, privilege escalation via auth log
# ─────────────────────────────────────────────────────────────────────────────

# Regex patterns for common auth log failure messages
_AUTH_FAIL_RE = re.compile(
    r"(Failed password|authentication failure|Invalid user|"
    r"FAILED LOGIN|pam_unix.*authentication failure|"
    r"Connection closed by authenticating user|Too many authentication)",
    re.IGNORECASE,
)
_SUDO_RE = re.compile(
    r"(sudo:.*COMMAND|su:.*session opened|sudo:.*authentication failure|"
    r"sudo:.*incorrect password)",
    re.IGNORECASE,
)
_SUDO_SUCCESS_RE = re.compile(
    r"sudo:.*COMMAND=",
    re.IGNORECASE,
)


class AuthLogMonitor:
    """
    Tails the system authentication log to count failure and sudo events
    per measurement window. Uses file seek to avoid re-reading old lines.
    """

    def __init__(self) -> None:
        self._path    = self._find_log()
        self._pos     = 0            # byte position in log file
        self._fail_count  = 0
        self._sudo_count  = 0
        self._lock    = threading.Lock()

        if self._path:
            try:
                self._pos = os.path.getsize(self._path)
                log.info("Auth log monitor: %s (starting at byte %d)", self._path, self._pos)
            except OSError:
                pass
        else:
            log.warning("Auth log monitor: no auth log found — host auth rules disabled")

    @staticmethod
    def _find_log() -> Optional[str]:
        for p in AUTH_LOG_CANDIDATES:
            if os.path.exists(p) and os.access(p, os.R_OK):
                return p
        return None

    def poll(self) -> None:
        """Called periodically to read new log lines since last poll."""
        if not self._path:
            return
        try:
            size = os.path.getsize(self._path)
        except OSError:
            return

        if size < self._pos:
            # Log was rotated — reset to beginning
            self._pos = 0

        if size == self._pos:
            return

        try:
            with open(self._path, "r", errors="replace") as fh:
                fh.seek(self._pos)
                new_lines = fh.read(size - self._pos)
                self._pos = fh.tell()
        except OSError:
            return

        fail_delta = 0
        sudo_delta = 0
        for line in new_lines.splitlines():
            if _AUTH_FAIL_RE.search(line):
                fail_delta += 1
            if _SUDO_RE.search(line):
                sudo_delta += 1

        with self._lock:
            self._fail_count += fail_delta
            self._sudo_count += sudo_delta

    def drain_counts(self) -> Tuple[int, int]:
        """Returns (auth_failures, sudo_events) since last drain and resets counters."""
        with self._lock:
            f, s = self._fail_count, self._sudo_count
            self._fail_count = 0
            self._sudo_count = 0
        return f, s

    def available(self) -> bool:
        return self._path is not None


# ─────────────────────────────────────────────────────────────────────────────
# HOST — PROCESS MONITOR
# Detects: abnormal process spawn rates
# ─────────────────────────────────────────────────────────────────────────────

class ProcessMonitor:
    """
    Uses psutil to count new processes spawned since last window.
    Tracks PIDs seen in the previous window; new PIDs are counted as spawns.
    """

    def __init__(self) -> None:
        self._available = PSUTIL_OK
        self._known_pids: Set[int] = set()

        if self._available:
            try:
                self._known_pids = {p.pid for p in psutil.process_iter()}
                log.info("Process monitor: active  (%d initial processes)", len(self._known_pids))
            except Exception as exc:
                log.warning("Process monitor: psutil error: %s", exc)
                self._available = False
        else:
            log.warning("Process monitor: psutil not installed — process rule disabled")

    def count_new_processes(self) -> int:
        """Returns count of processes spawned since last call."""
        if not self._available:
            return 0
        try:
            current_pids = {p.pid for p in psutil.process_iter()}
        except Exception:
            return 0
        new_pids         = current_pids - self._known_pids
        self._known_pids = current_pids
        return len(new_pids)

    def available(self) -> bool:
        return self._available


# ─────────────────────────────────────────────────────────────────────────────
# HOST — FILE INTEGRITY MONITOR
# Detects: unauthorized modification of critical system files
# ─────────────────────────────────────────────────────────────────────────────

class FileIntegrityMonitor:
    """
    Maintains SHA-256 hashes of monitored files and polls for changes
    at FILE_CHECK_INTERVAL seconds. Raises an alert on mismatch.
    Thread-safe: runs in its own background thread.
    """

    def __init__(self) -> None:
        self._hashes:   Dict[str, str]   = {}
        self._missing:  Set[str]         = set()
        self._stop      = threading.Event()
        self._thread    = threading.Thread(
            target=self._run, daemon=True, name="fim"
        )
        self._lock      = threading.Lock()
        self._pending_alerts: List[str]  = []

        self._baseline()
        self._thread.start()
        log.info("File integrity monitor: watching %d path(s)", len(MONITORED_FILES))

    @staticmethod
    def _hash(path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return None

    def _baseline(self) -> None:
        for path in MONITORED_FILES:
            h = self._hash(path)
            if h is None:
                self._missing.add(path)
                log.warning("FIM: cannot read %s — skipping", path)
            else:
                self._hashes[path] = h
                log.debug("FIM baseline: %s  %s", h[:12], path)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(FILE_CHECK_INTERVAL)
            if self._stop.is_set():
                break
            for path in MONITORED_FILES:
                if path in self._missing:
                    continue
                current = self._hash(path)
                if current is None:
                    continue
                known = self._hashes.get(path)
                if known and current != known:
                    alert_msg = (
                        f"File tampered: {path} | "
                        f"prev={known[:16]}... new={current[:16]}..."
                    )
                    log.warning("FIM: %s", alert_msg)
                    with self._lock:
                        self._pending_alerts.append(alert_msg)
                    # Update hash so we only alert once per change
                    self._hashes[path] = current

    def drain_alerts(self) -> List[str]:
        with self._lock:
            out, self._pending_alerts = self._pending_alerts, []
        return out

    def stop(self) -> None:
        self._stop.set()


# ─────────────────────────────────────────────────────────────────────────────
# ADAPTIVE BASELINE  (network + host metrics combined)
# ─────────────────────────────────────────────────────────────────────────────

class Baseline:
    """
    Records p99 peaks during baseline phase for both network and host metrics.
    Thresholds = max(hard_floor, p99_peak * THRESHOLD_MULTIPLIER).
    """

    def __init__(self) -> None:
        self._s: Dict[str, List[float]] = {
            "total": [], "syn": [], "udp": [], "icmp": [],
            "auth_fail": [], "sudo": [], "proc_spawn": [],
        }
        # Network thresholds
        self.thr_total = float(TOTAL_FLOOR)
        self.thr_syn   = float(SYN_FLOOR)
        self.thr_udp   = float(UDP_FLOOR)
        self.thr_icmp  = float(ICMP_FLOOR)
        # Host thresholds
        self.thr_auth_fail  = float(AUTH_FAIL_FLOOR)
        self.thr_sudo       = float(SUDO_EVENT_FLOOR)
        self.thr_proc_spawn = float(PROCESS_SPAWN_FLOOR)

    def record(self, nws: NetworkWindowStats,
               auth_fail: int, sudo_count: int, proc_spawn: int) -> None:
        self._s["total"].append(nws.total_rate)
        self._s["syn"].append(nws.syn_rate)
        self._s["udp"].append(nws.udp_rate)
        self._s["icmp"].append(nws.icmp_rate)
        self._s["auth_fail"].append(float(auth_fail))
        self._s["sudo"].append(float(sudo_count))
        self._s["proc_spawn"].append(float(proc_spawn))

    @staticmethod
    def _p99(vals: List[float]) -> float:
        if not vals:
            return 0.0
        s = sorted(vals)
        return s[max(0, int(len(s) * 0.99) - 1)]

    def finalise(self) -> None:
        pt  = self._p99(self._s["total"])
        ps  = self._p99(self._s["syn"])
        pu  = self._p99(self._s["udp"])
        pi  = self._p99(self._s["icmp"])
        paf = self._p99(self._s["auth_fail"])
        psd = self._p99(self._s["sudo"])
        ppr = self._p99(self._s["proc_spawn"])

        self.thr_total      = max(TOTAL_FLOOR,          pt  * THRESHOLD_MULTIPLIER)
        self.thr_syn        = max(SYN_FLOOR,            ps  * THRESHOLD_MULTIPLIER)
        self.thr_udp        = max(UDP_FLOOR,            pu  * THRESHOLD_MULTIPLIER)
        self.thr_icmp       = max(ICMP_FLOOR,           pi  * THRESHOLD_MULTIPLIER)
        self.thr_auth_fail  = max(AUTH_FAIL_FLOOR,      paf * THRESHOLD_MULTIPLIER)
        self.thr_sudo       = max(SUDO_EVENT_FLOOR,     psd * THRESHOLD_MULTIPLIER)
        self.thr_proc_spawn = max(PROCESS_SPAWN_FLOOR,  ppr * THRESHOLD_MULTIPLIER)

        log.info(
            "Baseline complete — network p99: "
            "total=%.1f/s  syn=%.1f/s  udp=%.1f/s  icmp=%.1f/s",
            pt, ps, pu, pi,
        )
        log.info(
            "Baseline complete — host p99: "
            "auth_fail=%.1f/win  sudo=%.1f/win  proc_spawn=%.1f/win",
            paf, psd, ppr,
        )
        log.info(
            "Network thresholds: total=%.0f/s  syn=%.0f/s  udp=%.0f/s  icmp=%.0f/s",
            self.thr_total, self.thr_syn, self.thr_udp, self.thr_icmp,
        )
        log.info(
            "Host thresholds: auth_fail=%.0f/win  sudo=%.0f/win  proc_spawn=%.0f/win",
            self.thr_auth_fail, self.thr_sudo, self.thr_proc_spawn,
        )
        write_alert(
            "HIDS entered DETECTION mode",
            "net: syn=%.0f udp=%.0f icmp=%.0f total=%.0f | "
            "host: auth_fail=%.0f sudo=%.0f proc_spawn=%.0f"
            % (self.thr_syn, self.thr_udp, self.thr_icmp, self.thr_total,
               self.thr_auth_fail, self.thr_sudo, self.thr_proc_spawn),
        )


# ─────────────────────────────────────────────────────────────────────────────
# RULE ENGINE  (network + host rules)
# ─────────────────────────────────────────────────────────────────────────────

class RuleEngine:

    def __init__(self, baseline: Baseline) -> None:
        self._b          = baseline
        self._streak:     Dict[str, int]   = collections.defaultdict(int)
        self._last_alert: Dict[str, float] = collections.defaultdict(float)

    # ── internal helpers ──────────────────────────────────────────────────────

    def _arm(self, rule: str, kind: str, detail: str,
             confirm: int = CONFIRM_WINDOWS) -> None:
        """Increment streak; fire alert if streak >= confirm and cooldown elapsed."""
        self._streak[rule] += 1
        if self._streak[rule] < confirm:
            log.debug("[SUSPECT] %-28s  streak=%d/%d",
                      rule, self._streak[rule], confirm)
            return
        now  = time.monotonic()
        wait = COOLDOWN_SECS - (now - self._last_alert[rule])
        if wait > 0:
            log.debug("[COOLDOWN] %-28s  %.0fs left", rule, wait)
            return
        self._last_alert[rule] = now
        self._streak[rule]     = 0
        write_alert(kind, detail)

    def _arm_immediate(self, rule: str, kind: str, detail: str) -> None:
        """Fire alert immediately (no confirmation window) subject to cooldown."""
        self._arm(rule, kind, detail, confirm=1)

    def _clear(self, rule: str) -> None:
        if self._streak.get(rule):
            log.debug("[CLEAR] %-28s  streak reset", rule)
            self._streak[rule] = 0

    # ── evaluation ────────────────────────────────────────────────────────────

    def evaluate(
        self,
        nws:        NetworkWindowStats,
        auth_fail:  int,
        sudo_count: int,
        proc_spawn: int,
        fim_alerts: List[str],
    ) -> None:
        b           = self._b
        proto_fired = False

        # ── HOST RULES ────────────────────────────────────────────────────────

        # Rule H1 — Brute-force / failed login
        if auth_fail > b.thr_auth_fail:
            self._arm_immediate(
                "brute_force", "Brute-force / failed login",
                "failures=%d (thr=%.0f) in window=%.0fs"
                % (auth_fail, b.thr_auth_fail, WINDOW_SECONDS),
            )
        else:
            self._clear("brute_force")

        # Rule H2 — Privilege escalation (sudo/su abuse)
        if sudo_count > b.thr_sudo:
            self._arm_immediate(
                "priv_escalation", "Privilege escalation",
                "sudo_su_events=%d (thr=%.0f) in window=%.0fs"
                % (sudo_count, b.thr_sudo, WINDOW_SECONDS),
            )
        else:
            self._clear("priv_escalation")

        # Rule H3 — Abnormal process spawn rate
        if proc_spawn > b.thr_proc_spawn:
            self._arm_immediate(
                "proc_anomaly", "Suspicious process activity",
                "new_procs=%d (thr=%.0f) in window=%.0fs"
                % (proc_spawn, b.thr_proc_spawn, WINDOW_SECONDS),
            )
        else:
            self._clear("proc_anomaly")

        # Rule H4 — File integrity violations  (event-driven, no cooldown logic)
        for alert_msg in fim_alerts:
            write_alert("File integrity violation", alert_msg)

        # ── NETWORK RULES ─────────────────────────────────────────────────────

        # Rule N1 — SYN flood
        if nws.syn_rate > b.thr_syn and nws.syn_ratio > SYN_RATIO_MIN:
            self._arm(
                "syn_flood", "SYN flood",
                "syn=%.0f/s (thr=%.0f) ratio=%.0f%% tcp=%d syn=%d"
                % (nws.syn_rate, b.thr_syn,
                   nws.syn_ratio * 100, nws.tcp_count, nws.syn_count),
            )
            proto_fired = True
        else:
            self._clear("syn_flood")

        # Rule N2 — UDP flood
        if nws.udp_rate > b.thr_udp:
            self._arm(
                "udp_flood", "UDP flood",
                "udp=%.0f/s (thr=%.0f) pkts=%d"
                % (nws.udp_rate, b.thr_udp, nws.udp_count),
            )
            proto_fired = True
        else:
            self._clear("udp_flood")

        # Rule N3 — ICMP flood
        if nws.icmp_rate > b.thr_icmp:
            self._arm(
                "icmp_flood", "ICMP flood",
                "icmp=%.0f/s (thr=%.0f) pkts=%d"
                % (nws.icmp_rate, b.thr_icmp, nws.icmp_count),
            )
            proto_fired = True
        else:
            self._clear("icmp_flood")

        # Rule N4 — Volumetric DoS
        if nws.total_rate > b.thr_total and not proto_fired:
            self._arm(
                "vol_flood", "Volumetric DoS",
                "rate=%.0f/s (thr=%.0f) tcp=%d udp=%d icmp=%d"
                % (nws.total_rate, b.thr_total,
                   nws.tcp_count, nws.udp_count, nws.icmp_count),
            )
        else:
            self._clear("vol_flood")

        # Rule N5 — Port scan (per source IP)
        active: Set[str] = set()
        for ip, spread in nws.src_port_spread.items():
            if spread >= PORT_SCAN_THRESHOLD:
                key = "scan_" + ip
                active.add(key)
                self._arm(
                    key, "Port scan",
                    "src=%s ports=%d (thr=%d)" % (ip, spread, PORT_SCAN_THRESHOLD),
                )
        for key in list(self._streak):
            if key.startswith("scan_") and key not in active:
                self._clear(key)

        log.debug(
            "[WIN] net total=%.0f  syn=%.0f(%.0f%%)  udp=%.0f  icmp=%.0f | "
            "host auth_fail=%d  sudo=%d  proc=%d  fim=%d",
            nws.total_rate, nws.syn_rate, nws.syn_ratio * 100,
            nws.udp_rate, nws.icmp_rate,
            auth_fail, sudo_count, proc_spawn, len(fim_alerts),
        )


# ─────────────────────────────────────────────────────────────────────────────
# AUTH LOG POLLER THREAD
# Continuously polls the auth log so events are captured between windows.
# ─────────────────────────────────────────────────────────────────────────────

class AuthPoller(threading.Thread):
    """Polls auth log every 0.5 s so no events are missed between windows."""

    def __init__(self, monitor: AuthLogMonitor) -> None:
        super().__init__(daemon=True, name="auth_poller")
        self._monitor = monitor
        self._stop    = threading.Event()

    def run(self) -> None:
        while not self._stop.is_set():
            self._monitor.poll()
            self._stop.wait(0.5)

    def stop(self) -> None:
        self._stop.set()


# ─────────────────────────────────────────────────────────────────────────────
# HIDS ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class HIDS:

    def __init__(self) -> None:
        iface           = get_interface()
        self._buf       = PacketBuffer()
        self._sniffer   = Sniffer(self._buf, iface)

        # Host monitors
        self._auth_mon  = AuthLogMonitor()
        self._auth_poll = AuthPoller(self._auth_mon)
        self._proc_mon  = ProcessMonitor()
        self._fim       = FileIntegrityMonitor()

        self._baseline  = Baseline()
        self._engine: Optional[RuleEngine] = None

        self._phase       = "baseline"
        self._phase_start = time.monotonic()
        self._windows     = 0
        self._zero_streak = 0
        self._running     = True

        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT,  self._on_signal)

    def _on_signal(self, sig: int, _frame: object) -> None:
        log.info("Signal %s — shutting down.", signal.Signals(sig).name)
        self._running = False

    def run(self) -> None:
        log.info(
            "Ulinzi HIDS starting  |  baseline=%ds  window=%ds  "
            "multiplier=%dx  confirm=%d  cooldown=%ds",
            BASELINE_SECONDS, WINDOW_SECONDS,
            THRESHOLD_MULTIPLIER, CONFIRM_WINDOWS, COOLDOWN_SECS,
        )
        log.info(
            "Host monitors: auth_log=%s  psutil=%s  fim=%d files",
            "YES" if self._auth_mon.available() else "NO (no auth log)",
            "YES" if self._proc_mon.available()  else "NO (install psutil)",
            len([f for f in MONITORED_FILES if f not in self._fim._missing]),
        )
        write_alert(
            "HIDS started",
            "baseline=%ds window=%ds multiplier=%dx "
            "floors: syn=%d udp=%d icmp=%d total=%d "
            "auth_fail=%d sudo=%d proc_spawn=%d"
            % (BASELINE_SECONDS, WINDOW_SECONDS, THRESHOLD_MULTIPLIER,
               SYN_FLOOR, UDP_FLOOR, ICMP_FLOOR, TOTAL_FLOOR,
               AUTH_FAIL_FLOOR, SUDO_EVENT_FLOOR, PROCESS_SPAWN_FLOOR),
        )

        self._sniffer.start()
        self._auth_poll.start()

        try:
            while self._running:
                time.sleep(WINDOW_SECONDS)
                if not self._running:
                    break

                # Collect window data
                pkts        = self._buf.drain()
                nws         = compute_network_stats(pkts, WINDOW_SECONDS)
                auth_fail, sudo_count = self._auth_mon.drain_counts()
                proc_spawn  = self._proc_mon.count_new_processes()
                fim_alerts  = self._fim.drain_alerts()

                self._windows += 1

                if not pkts:
                    self._zero_streak += 1
                    if self._zero_streak == ZERO_TRAFFIC_WARN_AFTER:
                        log.warning(
                            "No packets captured for %d windows — "
                            "generate traffic:  ping -c 5 8.8.8.8",
                            self._zero_streak,
                        )
                else:
                    self._zero_streak = 0

                # ── BASELINE ──────────────────────────────────────────────────
                if self._phase == "baseline":
                    self._baseline.record(nws, auth_fail, sudo_count, proc_spawn)
                    elapsed   = time.monotonic() - self._phase_start
                    remaining = max(0.0, BASELINE_SECONDS - elapsed)

                    log.info(
                        "[BASELINE %3.0fs left]  pkts=%4d  "
                        "net: total=%.1f/s syn=%.1f/s udp=%.1f/s icmp=%.1f/s | "
                        "host: auth_fail=%d sudo=%d proc=%d fim=%d",
                        remaining, len(pkts),
                        nws.total_rate, nws.syn_rate, nws.udp_rate, nws.icmp_rate,
                        auth_fail, sudo_count, proc_spawn, len(fim_alerts),
                    )

                    if elapsed >= BASELINE_SECONDS:
                        self._baseline.finalise()
                        self._engine = RuleEngine(self._baseline)
                        self._phase  = "detecting"
                        log.info("Detection ARMED — watching for host and network attacks.")

                # ── DETECTION ─────────────────────────────────────────────────
                else:
                    log.info(
                        "[DETECTING]            pkts=%4d  "
                        "net: total=%.1f/s syn=%.1f/s udp=%.1f/s icmp=%.1f/s | "
                        "host: auth_fail=%d sudo=%d proc=%d fim=%d",
                        len(pkts),
                        nws.total_rate, nws.syn_rate, nws.udp_rate, nws.icmp_rate,
                        auth_fail, sudo_count, proc_spawn, len(fim_alerts),
                    )
                    self._engine.evaluate(
                        nws, auth_fail, sudo_count, proc_spawn, fim_alerts
                    )

        finally:
            self._sniffer.stop()
            self._auth_poll.stop()
            self._fim.stop()
            log.info("HIDS stopped after %d windows.", self._windows)
            write_alert("HIDS stopped", "windows=%d" % self._windows)


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    HIDS().run()