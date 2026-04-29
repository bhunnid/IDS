"""
ids_main.py  —  Network Intrusion Detection System for Kali Linux

HOW IT WORKS
------------
Phase 1  BASELINE  (60 seconds)
    The IDS listens silently and records the p99 peak packet rates on your
    network across 3-second windows.  Detection thresholds are set to
    max(hard_floor, p99_peak * THRESHOLD_MULTIPLIER).
    Do NOT run attacks during this phase.

Phase 2  DETECTION
    Five rules evaluate every 3-second window.  An alert fires only when:
      - the metric exceeds the computed threshold, AND
      - the rule triggers for CONFIRM_WINDOWS consecutive windows, AND
      - the per-rule cooldown timer has elapsed.

    Rules:
      SYN flood   — syn_rate > threshold  AND  >70% of TCP are SYNs
      UDP flood   — udp_rate > threshold
      ICMP flood  — icmp_rate > threshold
      Volumetric  — total_rate > threshold (only if no protocol rule fired)
      Port scan   — one source IP touches >= 50 distinct dst ports in 3 s

TUNED FOR IDLE KALI VM
    Normal baseline on an idle VM is ~6 pkt/s total.  Hard floors are set
    so that hping3/nmap attacks (hundreds-to-thousands of packets per second)
    are always detected, while normal idle background noise (ARP, mDNS, DNS,
    NTP at ~6 pkt/s) never triggers alerts.

ALERT FORMAT  (appended to alerts.log)
    [YYYY-MM-DD HH:MM:SS] ALERT: <kind> | <detail>

ATTACK COMMANDS  (run in a second terminal)
    SYN flood  : sudo hping3 -S --flood -V -p 80 <target-ip>
    UDP flood  : sudo hping3 --udp --flood -p 53 <target-ip>
    ICMP flood : sudo hping3 --icmp --flood <target-ip>
    Port scan  : sudo nmap -sS -p 1-1000 --min-rate 500 <target-ip>
"""

from __future__ import annotations

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
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# Force a specific interface name if auto-detect picks the wrong one.
# Find yours with:  ip link show
# Examples:  "eth0"  "ens33"  "enp0s3"  "wlan0"
# Leave as None to auto-detect.
INTERFACE = None

BASELINE_SECONDS     = 60   # seconds to observe normal traffic
WINDOW_SECONDS       = 3    # measurement interval in seconds
THRESHOLD_MULTIPLIER = 4    # adaptive threshold = p99_peak * this value

# ── Hard floors ───────────────────────────────────────────────────────────────
# These are the dominant protection on an idle VM.
# Thresholds = max(floor, adaptive).  Floors always win when baseline is low.
#
#  Idle VM normal traffic  :  SYN ~0/s,  UDP ~2/s,  ICMP ~0/s,  total ~6/s
#  hping3 SYN flood        :  SYN ~5000/s
#  hping3 UDP flood        :  UDP ~8000/s
#  hping3 ICMP flood       :  ICMP ~5000/s
#  nmap -sS port scan      :  SYN ~200-600/s on target
#
SYN_FLOOR   = 500    # SYN packets/s
UDP_FLOOR   = 2000   # UDP packets/s
ICMP_FLOOR  = 200    # ICMP packets/s
TOTAL_FLOOR = 3000   # total packets/s

SYN_RATIO_MIN       = 0.70  # fraction of TCP that must be SYNs for a flood
PORT_SCAN_THRESHOLD = 50    # distinct dst ports from one IP in one window
CONFIRM_WINDOWS     = 2     # consecutive windows before alert fires (2*3s = 6s)
COOLDOWN_SECS       = 60    # seconds before same rule can fire again

ALERT_LOG             = "alerts.log"
INFO_LOG              = "ids.log"
ZERO_TRAFFIC_WARN_AFTER = 5   # warn after this many consecutive zero-pkt windows

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging() -> None:
    fmt = logging.Formatter(
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
log = logging.getLogger("ids")


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
# INTERFACE DETECTION
# ─────────────────────────────────────────────────────────────────────────────

_VIRTUAL = ("lo", "virbr", "docker", "br-", "veth", "tun", "tap",
            "vmnet", "vboxnet", "dummy", "sit")


def _is_virtual(name: str) -> bool:
    return any(name.startswith(p) for p in _VIRTUAL)


def _candidate_interfaces() -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []

    def add(name: str) -> None:
        name = name.strip()
        if name and name not in seen and not _is_virtual(name):
            seen.add(name)
            result.append(name)

    # 1. Default route interface — most reliable on VMs
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

    # 2. Kernel interface list
    try:
        for _, name in socket.if_nameindex():
            add(name)
    except Exception:
        pass

    # 3. /proc/net/dev
    try:
        with open("/proc/net/dev") as fh:
            for line in fh:
                if ":" in line:
                    add(line.split(":")[0].strip())
    except OSError:
        pass

    # 4. /sys/class/net
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            add(name)
    except OSError:
        pass

    # Common Kali VM interface names as last-resort fallbacks
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
        log.warning("No candidate passed bind test — trying: %s",
                    candidates[0] if candidates else "eth0")
    else:
        log.info("Not root — skipping bind test, selected: %s",
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
                 dport: int = 0, is_syn: bool = False) -> None:
        self.src_ip = src_ip
        self.proto  = proto
        self.dport  = dport
        self.is_syn = is_syn


def parse_packet(raw: bytes) -> Optional[Packet]:
    """Parse a raw Ethernet frame. Returns None for non-IPv4 or malformed."""
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
        is_syn = bool(flags & 0x02) and not bool(flags & 0x10)  # SYN not SYN-ACK

    elif proto == PROTO_UDP and len(payload) >= 4:
        dport = struct.unpack_from("!H", payload, 2)[0]

    return Packet(src_ip, proto, dport, is_syn)


# ─────────────────────────────────────────────────────────────────────────────
# PACKET BUFFER  (thread-safe)
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


# ─────────────────────────────────────────────────────────────────────────────
# SNIFFER THREAD
# ─────────────────────────────────────────────────────────────────────────────

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
            log.critical("Permission denied — run with:  sudo python3 ids_main.py")
            os._exit(1)
        except OSError as exc:
            log.critical(
                "Cannot bind to %r: %s\n"
                "  Check interfaces with:  ip link show\n"
                "  Then set INTERFACE = 'your_iface' at the top of ids_main.py",
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
# WINDOW STATISTICS
# ─────────────────────────────────────────────────────────────────────────────

class WindowStats:
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


def compute_stats(packets: List[Packet], window_secs: float) -> WindowStats:
    ws        = WindowStats()
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
# ADAPTIVE BASELINE
# ─────────────────────────────────────────────────────────────────────────────

class Baseline:
    """
    Measures p99 peak rates during baseline phase.
    Final thresholds = max(hard_floor, p99_peak * THRESHOLD_MULTIPLIER).
    On an idle VM the hard floors always dominate.
    """

    def __init__(self) -> None:
        self._s: Dict[str, List[float]] = {
            "total": [], "syn": [], "udp": [], "icmp": [],
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
            "Baseline complete — p99 peaks: "
            "total=%.1f/s  syn=%.1f/s  udp=%.1f/s  icmp=%.1f/s",
            pt, ps, pu, pi,
        )
        log.info(
            "Detection thresholds: "
            "total=%.0f/s  syn=%.0f/s  udp=%.0f/s  icmp=%.0f/s",
            self.thr_total, self.thr_syn, self.thr_udp, self.thr_icmp,
        )
        write_alert(
            "IDS entered DETECTION mode",
            "thr_total=%.0f/s thr_syn=%.0f/s thr_udp=%.0f/s thr_icmp=%.0f/s"
            % (self.thr_total, self.thr_syn, self.thr_udp, self.thr_icmp),
        )


# ─────────────────────────────────────────────────────────────────────────────
# RULE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class RuleEngine:

    def __init__(self, baseline: Baseline) -> None:
        self._b           = baseline
        self._streak:      Dict[str, int]   = collections.defaultdict(int)
        self._last_alert:  Dict[str, float] = collections.defaultdict(float)

    def _arm(self, rule: str, kind: str, detail: str) -> None:
        self._streak[rule] += 1
        if self._streak[rule] < CONFIRM_WINDOWS:
            log.debug("[SUSPECT] %-22s  streak=%d/%d",
                      rule, self._streak[rule], CONFIRM_WINDOWS)
            return
        now  = time.monotonic()
        wait = COOLDOWN_SECS - (now - self._last_alert[rule])
        if wait > 0:
            log.debug("[COOLDOWN] %-22s  %.0fs left", rule, wait)
            return
        self._last_alert[rule] = now
        self._streak[rule]     = 0
        write_alert(kind, detail)

    def _clear(self, rule: str) -> None:
        if self._streak[rule]:
            log.debug("[CLEAR] %-22s  streak reset", rule)
            self._streak[rule] = 0

    def evaluate(self, ws: WindowStats) -> None:
        b           = self._b
        proto_fired = False

        # Rule 1 — SYN flood
        if ws.syn_rate > b.thr_syn and ws.syn_ratio > SYN_RATIO_MIN:
            self._arm(
                "syn_flood", "SYN flood",
                "syn=%.0f/s (thr=%.0f) ratio=%.0f%% tcp=%d syn=%d"
                % (ws.syn_rate, b.thr_syn,
                   ws.syn_ratio * 100, ws.tcp_count, ws.syn_count),
            )
            proto_fired = True
        else:
            self._clear("syn_flood")

        # Rule 2 — UDP flood
        if ws.udp_rate > b.thr_udp:
            self._arm(
                "udp_flood", "UDP flood",
                "udp=%.0f/s (thr=%.0f) pkts=%d"
                % (ws.udp_rate, b.thr_udp, ws.udp_count),
            )
            proto_fired = True
        else:
            self._clear("udp_flood")

        # Rule 3 — ICMP flood
        if ws.icmp_rate > b.thr_icmp:
            self._arm(
                "icmp_flood", "ICMP flood",
                "icmp=%.0f/s (thr=%.0f) pkts=%d"
                % (ws.icmp_rate, b.thr_icmp, ws.icmp_count),
            )
            proto_fired = True
        else:
            self._clear("icmp_flood")

        # Rule 4 — Volumetric DoS (only fires if no protocol rule already fired)
        if ws.total_rate > b.thr_total and not proto_fired:
            self._arm(
                "vol_flood", "Volumetric DoS",
                "rate=%.0f/s (thr=%.0f) tcp=%d udp=%d icmp=%d"
                % (ws.total_rate, b.thr_total,
                   ws.tcp_count, ws.udp_count, ws.icmp_count),
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
                    "src=%s ports=%d (thr=%d)" % (ip, spread, PORT_SCAN_THRESHOLD),
                )
        for key in list(self._streak):
            if key.startswith("scan_") and key not in active:
                self._clear(key)

        log.debug(
            "[WIN] total=%.0f  syn=%.0f(%.0f%%)  udp=%.0f  icmp=%.0f  spread_max=%d",
            ws.total_rate, ws.syn_rate, ws.syn_ratio * 100,
            ws.udp_rate, ws.icmp_rate,
            max(ws.src_port_spread.values()) if ws.src_port_spread else 0,
        )


# ─────────────────────────────────────────────────────────────────────────────
# IDS ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class IDS:

    def __init__(self) -> None:
        iface           = get_interface()
        self._buf       = PacketBuffer()
        self._sniffer   = Sniffer(self._buf, iface)
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
            "IDS starting  |  baseline=%ds  window=%ds  "
            "multiplier=%dx  confirm=%d  cooldown=%ds",
            BASELINE_SECONDS, WINDOW_SECONDS,
            THRESHOLD_MULTIPLIER, CONFIRM_WINDOWS, COOLDOWN_SECS,
        )
        log.info(
            "Hard floors   |  syn=%d/s  udp=%d/s  icmp=%d/s  total=%d/s",
            SYN_FLOOR, UDP_FLOOR, ICMP_FLOOR, TOTAL_FLOOR,
        )
        write_alert(
            "IDS started",
            "baseline=%ds window=%ds multiplier=%dx "
            "floors: syn=%d udp=%d icmp=%d total=%d"
            % (BASELINE_SECONDS, WINDOW_SECONDS, THRESHOLD_MULTIPLIER,
               SYN_FLOOR, UDP_FLOOR, ICMP_FLOOR, TOTAL_FLOOR),
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

                if not pkts:
                    self._zero_streak += 1
                    if self._zero_streak == ZERO_TRAFFIC_WARN_AFTER:
                        log.warning(
                            "No packets captured for %d windows. "
                            "Generate traffic:  ping -c 5 8.8.8.8",
                            self._zero_streak,
                        )
                else:
                    self._zero_streak = 0

                # ── BASELINE ──────────────────────────────────────────────────
                if self._phase == "baseline":
                    self._baseline.record(ws)
                    elapsed   = time.monotonic() - self._phase_start
                    remaining = max(0.0, BASELINE_SECONDS - elapsed)

                    log.info(
                        "[BASELINE %3.0fs left]  pkts=%4d  "
                        "total=%.1f/s  syn=%.1f/s  udp=%.1f/s  icmp=%.1f/s",
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
                        "total=%.1f/s  syn=%.1f/s  udp=%.1f/s  icmp=%.1f/s",
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
