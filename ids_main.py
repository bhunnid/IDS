"""
ids_main.py  —  Network Intrusion Detection System for Kali Linux
==================================================================
No external dependencies.  Uses only Python standard library.
Requires root / sudo for raw packet capture (AF_PACKET socket).

FIXES IN THIS VERSION
---------------------
  Fix 1: Robust interface detection — 4-method cascade, works on all Kali VM
          interface naming conventions (ens33, eth0, enp0s3, wlan0, etc.)
          Logs the chosen interface clearly so you can verify.
  Fix 2: Python 3.9+ compatibility — removed X|None union syntax,
          uses Optional[] from typing instead (supported back to 3.5).
  Fix 3: Socket bind validation — tests the chosen interface before
          committing; cycles through fallback names on failure.
  Fix 4: Dependency check on startup — validates Flask is importable
          before running, prints clear install instruction if not.
  Fix 5: VM traffic awareness — if pkts=0 for first N windows, prints
          a reminder to generate test traffic (ping, curl, etc.).

HOW IT WORKS
------------
Phase 1 BASELINE (60 s by default)
    Listens silently and records the p99 peak of total, SYN, UDP and ICMP
    packet rates across 3-second windows.  Detection thresholds are set
    to THRESHOLD_MULTIPLIER × those peaks.  Do NOT attack during this phase.

Phase 2 DETECTION
    Five rules evaluate every 3-second window:
      SYN flood   — syn_rate > threshold  AND  >70% of TCP are SYNs
      UDP flood   — udp_rate > threshold
      ICMP flood  — icmp_rate > threshold  (hard floor: 50/s)
      Volumetric  — total_rate > threshold (only if no protocol rule fired)
      Port scan   — one source IP touches ≥50 distinct ports in one window
    Each rule needs CONFIRM_WINDOWS consecutive triggers before alerting,
    and obeys a per-rule COOLDOWN_SECS to prevent alert storms.

ALERT FORMAT (appended to alerts.log)
    [YYYY-MM-DD HH:MM:SS] ALERT: <kind> | <detail>

ATTACK COMMANDS (run in a second terminal on Kali)
    SYN flood  : sudo hping3 -S --flood -V -p 80 <target-ip>
    UDP flood  : sudo hping3 --udp --flood -p 53 <target-ip>
    ICMP flood : sudo hping3 --icmp --flood <target-ip>
    Port scan  : sudo nmap -sS -p 1-1000 --min-rate 500 <target-ip>

RUN
    sudo python3 ids_main.py
"""

from __future__ import annotations   # keeps Optional[] compatible everywhere

import os
import sys
import time
import signal
import socket
import struct
import logging
import subprocess
import threading
import collections
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Optional, Dict, Set, List

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  —  the only values you may need to change
# ─────────────────────────────────────────────────────────────────────────────

# Set to your interface name if auto-detect picks the wrong one.
# Examples: "eth0"  "ens33"  "enp0s3"  "wlan0"
# Leave as None to auto-detect.
INTERFACE = None

BASELINE_SECONDS    = 60    # seconds of normal traffic to learn from
WINDOW_SECONDS      = 3     # measurement interval
THRESHOLD_MULTIPLIER= 8     # alert threshold = peak × this value

# Hard floors — fire regardless of baseline (no legitimate traffic reaches these)
SYN_FLOOR    = 200    # SYN packets/s
UDP_FLOOR    = 1000   # UDP packets/s
ICMP_FLOOR   = 50     # ICMP packets/s
TOTAL_FLOOR  = 5000   # total packets/s

SYN_RATIO_MIN       = 0.70  # fraction of TCP that are SYNs → flood indicator
PORT_SCAN_THRESHOLD = 50    # distinct dst ports from one IP in one window
CONFIRM_WINDOWS     = 2     # consecutive windows before alert fires
COOLDOWN_SECS       = 60    # seconds before same rule can fire again

ALERT_LOG = "alerts.log"
INFO_LOG  = "ids.log"

# Warn if this many consecutive windows capture zero packets (likely no traffic)
ZERO_TRAFFIC_WARN_AFTER = 5

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY CHECK  (Fix 4)
# ─────────────────────────────────────────────────────────────────────────────

def _check_deps():
    """Validate Flask is installed before anything else."""
    try:
        import flask  # noqa: F401
    except ImportError:
        print("ERROR: Flask is required for the web panel.")
        print("       Install it with:  pip3 install flask")
        print("       (The IDS itself runs fine without Flask.)")
        # Don't exit — IDS can still run standalone, panel just won't work

_check_deps()

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging():
    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
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
log = logging.getLogger("ids")


def write_alert(kind: str, detail: str) -> None:
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] ALERT: {kind} | {detail}"
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(line + "\n")
    except OSError as e:
        log.error("Cannot write alert: %s", e)
    log.warning(">>> ALERT: %s | %s", kind, detail)


# ─────────────────────────────────────────────────────────────────────────────
# INTERFACE DETECTION  (Fix 1 + Fix 3)
# ─────────────────────────────────────────────────────────────────────────────

# Prefixes that are virtual/bridge interfaces — skip them in auto-detect
_VIRTUAL_PREFIXES = ("lo", "virbr", "docker", "br-", "veth", "tun", "tap",
                     "vmnet", "vboxnet", "dummy", "sit")


def _is_virtual(name: str) -> bool:
    return any(name.startswith(p) for p in _VIRTUAL_PREFIXES)


def _candidate_interfaces() -> List[str]:
    """
    Return candidate interface names from all available sources,
    best-first (default-route interface first).
    Deduplicates while preserving order.
    """
    seen: Set[str] = set()
    result: List[str] = []

    def add(name: str):
        name = name.strip()
        if name and name not in seen:
            seen.add(name)
            result.append(name)

    # Source 1: default route interface — most reliable on VMs
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            stderr=subprocess.DEVNULL, timeout=3
        ).decode()
        tokens = out.split()
        for i, tok in enumerate(tokens):
            if tok == "dev" and i + 1 < len(tokens):
                add(tokens[i + 1])
    except Exception:
        pass

    # Source 2: socket.if_nameindex() — kernel-provided list
    try:
        for _idx, name in socket.if_nameindex():
            if not _is_virtual(name):
                add(name)
    except Exception:
        pass

    # Source 3: /proc/net/dev
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    name = line.split(":")[0].strip()
                    if not _is_virtual(name):
                        add(name)
    except OSError:
        pass

    # Source 4: /sys/class/net
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if not _is_virtual(name):
                add(name)
    except OSError:
        pass

    # Append common Kali VM names as last-resort fallbacks
    for fb in ("eth0", "ens33", "ens3", "enp0s3", "ens160", "wlan0"):
        add(fb)

    return result


def _test_bind(iface: str) -> bool:
    """Return True if we can create an AF_PACKET socket on this interface."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(0x0003))
        s.bind((iface, 0))
        s.close()
        return True
    except OSError:
        return False


def get_interface() -> str:
    """
    Pick the best bindable interface.  Logs every step so the user can
    see exactly what was chosen and why.
    """
    if INTERFACE:
        log.info("Interface (configured): %s", INTERFACE)
        return INTERFACE

    candidates = _candidate_interfaces()
    log.info("Interface candidates: %s", candidates[:8])

    # Try each candidate — use first one that actually binds
    # (skip bind test if not root; we'll fail properly in Sniffer.run())
    if os.geteuid() == 0:
        for iface in candidates:
            if _test_bind(iface):
                log.info("Interface selected (bind test passed): %s", iface)
                return iface
        log.warning("No interface passed bind test — using first candidate: %s",
                    candidates[0] if candidates else "eth0")
    else:
        # Not root yet — just pick the best candidate; sudo will be needed
        log.info("Not root — skipping bind test.  Selected: %s",
                 candidates[0] if candidates else "eth0")

    return candidates[0] if candidates else "eth0"


# ─────────────────────────────────────────────────────────────────────────────
# PACKET PARSING
# ─────────────────────────────────────────────────────────────────────────────

PROTO_TCP  = 6
PROTO_UDP  = 17
PROTO_ICMP = 1
ETH_P_IP   = 0x0800
ETH_P_ALL  = 0x0003


class Packet:
    __slots__ = ("src_ip", "proto", "dport", "is_syn")

    def __init__(self, src_ip: str, proto: int,
                 dport: int = 0, is_syn: bool = False):
        self.src_ip = src_ip
        self.proto  = proto
        self.dport  = dport
        self.is_syn = is_syn


def parse_packet(raw: bytes) -> Optional[Packet]:   # Fix 2: Optional[] not X|None
    """
    Parse a raw Ethernet frame.  Returns None for non-IPv4 or malformed frames.
    Layout: Ethernet(14) + IP(>=20) + transport header
    """
    if len(raw) < 34:
        return None

    eth_type = struct.unpack_from("!H", raw, 12)[0]
    if eth_type != ETH_P_IP:
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
    dport   = 0
    is_syn  = False

    if proto == PROTO_TCP and len(payload) >= 14:
        dport  = struct.unpack_from("!H", payload, 2)[0]
        flags  = payload[13]
        # SYN=1, ACK=0  (pure SYN, not SYN-ACK)
        is_syn = bool(flags & 0x02) and not bool(flags & 0x10)

    elif proto == PROTO_UDP and len(payload) >= 4:
        dport = struct.unpack_from("!H", payload, 2)[0]

    # ICMP needs no extra fields

    return Packet(src_ip, proto, dport, is_syn)


# ─────────────────────────────────────────────────────────────────────────────
# PACKET BUFFER
# ─────────────────────────────────────────────────────────────────────────────

class PacketBuffer:
    def __init__(self):
        self._lock = threading.Lock()
        self._pkts: List[Packet] = []

    def put(self, pkt: Packet) -> None:
        with self._lock:
            self._pkts.append(pkt)

    def drain(self) -> List[Packet]:
        with self._lock:
            out, self._pkts = self._pkts, []
        return out


# ─────────────────────────────────────────────────────────────────────────────
# SNIFFER THREAD  (Fix 3: better bind error handling)
# ─────────────────────────────────────────────────────────────────────────────

class Sniffer(threading.Thread):

    def __init__(self, buf: PacketBuffer, iface: str):
        super().__init__(daemon=True, name="sniffer")
        self._buf   = buf
        self._iface = iface
        self._stop  = threading.Event()
        self._sock: Optional[socket.socket] = None

    def run(self) -> None:
        try:
            self._sock = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(ETH_P_ALL)
            )
            self._sock.bind((self._iface, 0))
            self._sock.settimeout(1.0)
            log.info("Sniffer bound to interface: %s", self._iface)
        except PermissionError:
            log.critical(
                "Permission denied opening raw socket.\n"
                "  Run with:  sudo python3 ids_main.py"
            )
            os._exit(1)
        except OSError as e:
            log.critical(
                "Cannot bind to interface %r: %s\n"
                "  Check available interfaces with:  ip link show\n"
                "  Then set INTERFACE = 'your_iface' at the top of ids_main.py",
                self._iface, e
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
# WINDOW STATISTICS
# ─────────────────────────────────────────────────────────────────────────────

class WindowStats:
    __slots__ = (
        "total_rate", "syn_rate", "udp_rate", "icmp_rate",
        "tcp_count",  "syn_count", "udp_count", "icmp_count",
        "syn_ratio",  "src_port_spread",
    )

    def __init__(self):
        self.total_rate  = 0.0
        self.syn_rate    = 0.0
        self.udp_rate    = 0.0
        self.icmp_rate   = 0.0
        self.tcp_count   = 0
        self.syn_count   = 0
        self.udp_count   = 0
        self.icmp_count  = 0
        self.syn_ratio   = 0.0
        self.src_port_spread: Dict[str, int] = {}


def compute_stats(packets: List[Packet], window_secs: float) -> WindowStats:
    ws = WindowStats()
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

    n  = len(packets)
    w  = window_secs
    ws.total_rate = n             / w
    ws.syn_rate   = ws.syn_count  / w
    ws.udp_rate   = ws.udp_count  / w
    ws.icmp_rate  = ws.icmp_count / w
    ws.syn_ratio  = (ws.syn_count / ws.tcp_count) if ws.tcp_count else 0.0
    ws.src_port_spread = {ip: len(ports) for ip, ports in src_ports.items()}
    return ws


# ─────────────────────────────────────────────────────────────────────────────
# ADAPTIVE BASELINE
# ─────────────────────────────────────────────────────────────────────────────

class Baseline:
    """Compute p99 peaks and set per-metric detection thresholds."""

    def __init__(self):
        self._s: Dict[str, List[float]] = {
            "total": [], "syn": [], "udp": [], "icmp": []
        }
        self.thr_total = float(TOTAL_FLOOR)
        self.thr_syn   = float(SYN_FLOOR)
        self.thr_udp   = float(UDP_FLOOR)
        self.thr_icmp  = float(ICMP_FLOOR)

    def record(self, ws: WindowStats) -> None:
        self._s["total"].append(ws.total_rate)
        self._s["syn"].append(ws.syn_rate)
        self._s["udp"].append(ws.udp_rate)
        self._s["icmp"].append(ws.icmp_rate)

    @staticmethod
    def _p99(vals: List[float]) -> float:
        if not vals:
            return 0.0
        s = sorted(vals)
        return s[max(0, int(len(s) * 0.99) - 1)]

    def finalise(self) -> None:
        pt = self._p99(self._s["total"])
        ps = self._p99(self._s["syn"])
        pu = self._p99(self._s["udp"])
        pi = self._p99(self._s["icmp"])

        self.thr_total = max(TOTAL_FLOOR, pt * THRESHOLD_MULTIPLIER)
        self.thr_syn   = max(SYN_FLOOR,   ps * THRESHOLD_MULTIPLIER)
        self.thr_udp   = max(UDP_FLOOR,   pu * THRESHOLD_MULTIPLIER)
        self.thr_icmp  = max(ICMP_FLOOR,  pi * THRESHOLD_MULTIPLIER)

        log.info(
            "Baseline complete — observed p99: "
            "total=%.1f/s  syn=%.1f/s  udp=%.1f/s  icmp=%.1f/s",
            pt, ps, pu, pi,
        )
        log.info(
            "Detection thresholds set: "
            "total=%.0f/s  syn=%.0f/s  udp=%.0f/s  icmp=%.0f/s",
            self.thr_total, self.thr_syn, self.thr_udp, self.thr_icmp,
        )
        write_alert(
            "IDS entered DETECTION mode",
            "thr_total=%.0f/s thr_syn=%.0f/s thr_udp=%.0f/s thr_icmp=%.0f/s"
            % (self.thr_total, self.thr_syn, self.thr_udp, self.thr_icmp)
        )


# ─────────────────────────────────────────────────────────────────────────────
# RULE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class RuleEngine:

    def __init__(self, baseline: Baseline):
        self._b          = baseline
        self._streak:     Dict[str, int]   = collections.defaultdict(int)
        self._last_alert: Dict[str, float] = collections.defaultdict(float)

    def _arm(self, rule: str, kind: str, detail: str) -> None:
        self._streak[rule] += 1
        if self._streak[rule] < CONFIRM_WINDOWS:
            log.debug("[SUSPECT] %-22s streak=%d/%d",
                      rule, self._streak[rule], CONFIRM_WINDOWS)
            return
        now  = time.monotonic()
        wait = COOLDOWN_SECS - (now - self._last_alert[rule])
        if wait > 0:
            log.debug("[COOLDOWN] %-22s %.0fs left", rule, wait)
            return
        self._last_alert[rule] = now
        self._streak[rule]     = 0
        write_alert(kind, detail)

    def _clear(self, rule: str) -> None:
        if self._streak[rule]:
            log.debug("[CLEAR] %-22s streak reset", rule)
            self._streak[rule] = 0

    def evaluate(self, ws: WindowStats) -> None:
        b            = self._b
        proto_fired  = False

        # Rule 1 — SYN flood
        if ws.syn_rate > b.thr_syn and ws.syn_ratio > SYN_RATIO_MIN:
            self._arm(
                "syn_flood", "SYN flood",
                "syn=%.0f/s (thr=%.0f) ratio=%.0f%% tcp=%d syn=%d"
                % (ws.syn_rate, b.thr_syn, ws.syn_ratio * 100,
                   ws.tcp_count, ws.syn_count)
            )
            proto_fired = True
        else:
            self._clear("syn_flood")

        # Rule 2 — UDP flood
        if ws.udp_rate > b.thr_udp:
            self._arm(
                "udp_flood", "UDP flood",
                "udp=%.0f/s (thr=%.0f) pkts=%d"
                % (ws.udp_rate, b.thr_udp, ws.udp_count)
            )
            proto_fired = True
        else:
            self._clear("udp_flood")

        # Rule 3 — ICMP flood
        if ws.icmp_rate > b.thr_icmp:
            self._arm(
                "icmp_flood", "ICMP flood",
                "icmp=%.0f/s (thr=%.0f) pkts=%d"
                % (ws.icmp_rate, b.thr_icmp, ws.icmp_count)
            )
            proto_fired = True
        else:
            self._clear("icmp_flood")

        # Rule 4 — Volumetric DoS (catch-all, no duplicate)
        if ws.total_rate > b.thr_total and not proto_fired:
            self._arm(
                "vol_flood", "Volumetric DoS",
                "rate=%.0f/s (thr=%.0f) tcp=%d udp=%d icmp=%d"
                % (ws.total_rate, b.thr_total,
                   ws.tcp_count, ws.udp_count, ws.icmp_count)
            )
        else:
            self._clear("vol_flood")

        # Rule 5 — Port scan (per source IP)
        active: Set[str] = set()
        for ip, spread in ws.src_port_spread.items():
            if spread >= PORT_SCAN_THRESHOLD:
                key = "scan_" + ip
                active.add(key)
                self._arm(
                    key, "Port scan",
                    "src=%s ports=%d (thr=%d)" % (ip, spread, PORT_SCAN_THRESHOLD)
                )
        for key in list(self._streak):
            if key.startswith("scan_") and key not in active:
                self._clear(key)

        log.debug(
            "[WIN] total=%.0f syn=%.0f(%.0f%%) udp=%.0f icmp=%.0f spread_max=%d",
            ws.total_rate, ws.syn_rate, ws.syn_ratio * 100,
            ws.udp_rate, ws.icmp_rate,
            max(ws.src_port_spread.values()) if ws.src_port_spread else 0,
        )


# ─────────────────────────────────────────────────────────────────────────────
# IDS ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class IDS:

    def __init__(self):
        iface           = get_interface()
        self._buf       = PacketBuffer()
        self._sniffer   = Sniffer(self._buf, iface)
        self._baseline  = Baseline()
        self._engine: Optional[RuleEngine] = None

        self._phase       = "baseline"
        self._phase_start = time.monotonic()
        self._windows     = 0
        self._zero_streak = 0   # consecutive zero-packet windows (Fix 5)
        self._running     = True

        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT,  self._on_signal)

    def _on_signal(self, sig: int, _frame) -> None:
        log.info("Signal %s received — shutting down.", signal.Signals(sig).name)
        self._running = False

    def run(self) -> None:
        log.info(
            "IDS starting  |  baseline=%ds  window=%ds  "
            "multiplier=%dx  confirm=%d  cooldown=%ds",
            BASELINE_SECONDS, WINDOW_SECONDS,
            THRESHOLD_MULTIPLIER, CONFIRM_WINDOWS, COOLDOWN_SECS,
        )
        write_alert(
            "IDS started",
            "baseline=%ds window=%ds multiplier=%dx"
            % (BASELINE_SECONDS, WINDOW_SECONDS, THRESHOLD_MULTIPLIER)
        )
        self._sniffer.start()

        try:
            while self._running:
                time.sleep(WINDOW_SECONDS)
                if not self._running:
                    break

                pkts = self._buf.drain()
                ws   = compute_stats(pkts, WINDOW_SECONDS)
                self._windows += 1

                # Fix 5: warn if no traffic is being captured
                if len(pkts) == 0:
                    self._zero_streak += 1
                    if self._zero_streak == ZERO_TRAFFIC_WARN_AFTER:
                        log.warning(
                            "No packets captured for %d consecutive windows. "
                            "Is network traffic flowing? "
                            "Try:  ping -c 5 8.8.8.8   or   curl http://example.com",
                            self._zero_streak,
                        )
                else:
                    self._zero_streak = 0

                # ── BASELINE ─────────────────────────────────────────────────
                if self._phase == "baseline":
                    self._baseline.record(ws)
                    elapsed   = time.monotonic() - self._phase_start
                    remaining = max(0.0, BASELINE_SECONDS - elapsed)

                    log.info(
                        "[BASELINE %3.0fs left]  pkts=%4d  "
                        "total=%.0f/s  syn=%.0f/s  udp=%.0f/s  icmp=%.0f/s",
                        remaining, len(pkts),
                        ws.total_rate, ws.syn_rate, ws.udp_rate, ws.icmp_rate,
                    )

                    if elapsed >= BASELINE_SECONDS:
                        self._baseline.finalise()
                        self._engine = RuleEngine(self._baseline)
                        self._phase  = "detecting"
                        log.info("Detection ARMED — watching for attacks.")

                # ── DETECTION ─────────────────────────────────────────────────
                else:
                    log.info(
                        "[DETECTING]            pkts=%4d  "
                        "total=%.0f/s  syn=%.0f/s  udp=%.0f/s  icmp=%.0f/s",
                        len(pkts),
                        ws.total_rate, ws.syn_rate, ws.udp_rate, ws.icmp_rate,
                    )
                    self._engine.evaluate(ws)

        finally:
            self._sniffer.stop()
            log.info("IDS stopped after %d windows.", self._windows)
            write_alert("IDS stopped", "windows=%d" % self._windows)


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    IDS().run()
