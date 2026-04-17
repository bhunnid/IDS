"""
ids_main.py  —  Network Intrusion Detection System for Kali Linux
==================================================================
Captures live traffic using a raw AF_PACKET socket (no Scapy, no tcpdump,
no external dependencies beyond the Python standard library).

HOW IT WORKS
------------
Phase 1 — BASELINE  (first 60 seconds, configurable)
    The IDS listens silently and records the peak packet rates on your
    network: total packets/s, SYN packets/s, UDP packets/s, ICMP packets/s.
    Using p99 of all 3-second windows so one burst doesn't inflate the
    baseline. DO NOT run an attack during this phase.

Phase 2 — DETECTION  (after baseline)
    Five rules fire based on hard multiples of YOUR measured baseline peaks.
    Traffic must exceed 8× your own normal peak (configurable) AND sustain
    that level for 2 consecutive windows (6 seconds) before any alert fires.
    A per-rule 60-second cooldown prevents alert storms.

RULES
-----
  SYN flood   : syn_rate  > baseline × 8  AND  >70% of TCP are SYNs
  UDP flood   : udp_rate  > baseline × 8
  ICMP flood  : icmp_rate > baseline × 8  (min floor: 50/s)
  Vol. DoS    : total_rate > baseline × 8 (only if no protocol rule fires)
  Port scan   : one IP touches ≥ 50 distinct ports in 3 seconds

ALERT FORMAT  (appended to alerts.log)
    [YYYY-MM-DD HH:MM:SS] ALERT: <kind> | <detail>

ATTACK SIMULATION (Kali tools)
    SYN flood   : sudo hping3 -S --flood -V -p 80 <target-ip>
    UDP flood   : sudo hping3 --udp --flood -p 53 <target-ip>
    ICMP flood  : sudo hping3 --icmp --flood <target-ip>
    Port scan   : sudo nmap -sS -p 1-1000 --min-rate 500 <target-ip>
    Slowloris   : slowhttptest -c 500 -H -g -o output -i 10 -r 200 -t GET -u http://<target-ip>/

RUN
    sudo python3 ids_main.py
"""

import os
import sys
import time
import signal
import socket
import struct
import logging
import threading
import collections
from datetime import datetime
from logging.handlers import RotatingFileHandler

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  —  edit these if needed
# ─────────────────────────────────────────────────────────────────────────────

# Network interface to capture on. None = auto-detect first non-loopback iface.
INTERFACE = None

# Seconds to observe normal traffic and build adaptive thresholds.
BASELINE_SECONDS = 60

# Measurement window (seconds). Packets in this window form one data point.
WINDOW_SECONDS = 3

# Alert when a metric exceeds this multiple of your own measured normal peak.
# 8 = must be 8× your measured normal. Lower = more sensitive, higher = quieter.
THRESHOLD_MULTIPLIER = 8

# Hard floors: alert regardless of baseline if these rates are exceeded.
# These numbers represent traffic NO legitimate device ever sends.
SYN_FLOOR   = 200    # SYN packets/s
UDP_FLOOR   = 1000   # UDP packets/s
ICMP_FLOOR  = 50     # ICMP packets/s
TOTAL_FLOOR = 5000   # Total packets/s

# SYN flood: minimum fraction of TCP packets that must be SYNs.
SYN_RATIO_MIN = 0.70

# Port scan: number of distinct destination ports from one IP in one window.
PORT_SCAN_THRESHOLD = 50

# Consecutive windows a rule must fire before an alert is written.
CONFIRM_WINDOWS = 2   # 2 × 3s = 6 seconds sustained

# Seconds before the same rule can fire again.
COOLDOWN_SECS = 60

ALERT_LOG = "alerts.log"
INFO_LOG  = "ids.log"

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


def write_alert(kind: str, detail: str):
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] ALERT: {kind} | {detail}"
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(line + "\n")
    except OSError as e:
        log.error("Cannot write alert file: %s", e)
    log.warning(">>> ALERT: %s | %s", kind, detail)

# ─────────────────────────────────────────────────────────────────────────────
# INTERFACE DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def get_interface() -> str:
    if INTERFACE:
        return INTERFACE
    # Pick first non-loopback interface from /proc/net/dev
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    iface = line.split(":")[0].strip()
                    if iface != "lo":
                        return iface
    except OSError:
        pass
    return "eth0"

# ─────────────────────────────────────────────────────────────────────────────
# PACKET CAPTURE  —  pure Python AF_PACKET raw socket
# ─────────────────────────────────────────────────────────────────────────────

# IP protocol numbers
PROTO_TCP  = 6
PROTO_UDP  = 17
PROTO_ICMP = 1

# Ethernet type for IPv4
ETH_P_IP   = 0x0800
ETH_P_ALL  = 0x0003   # capture everything


class Packet:
    """Parsed packet — only fields the IDS needs."""
    __slots__ = ("src_ip", "dst_ip", "proto", "dport", "is_syn")

    def __init__(self, src_ip, dst_ip, proto, dport=0, is_syn=False):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.proto  = proto
        self.dport  = dport
        self.is_syn = is_syn


def parse_packet(raw: bytes) -> Packet | None:
    """
    Parse a raw frame from AF_PACKET. Returns None for non-IPv4 or too-short.
    Ethernet (14) + IP (min 20) + transport header minimum.
    """
    if len(raw) < 34:   # 14 eth + 20 ip
        return None

    # Ethernet header: dst(6) src(6) type(2)
    eth_type = struct.unpack_from("!H", raw, 12)[0]
    if eth_type != ETH_P_IP:
        return None

    ip = raw[14:]
    if len(ip) < 20:
        return None

    ihl     = (ip[0] & 0x0F) * 4
    proto   = ip[9]
    src_ip  = socket.inet_ntoa(ip[12:16])
    dst_ip  = socket.inet_ntoa(ip[16:20])
    payload = ip[ihl:]

    dport  = 0
    is_syn = False

    if proto == PROTO_TCP and len(payload) >= 14:
        dport  = struct.unpack_from("!H", payload, 2)[0]
        flags  = payload[13]
        is_syn = bool(flags & 0x02) and not bool(flags & 0x10)  # SYN without ACK

    elif proto == PROTO_UDP and len(payload) >= 4:
        dport = struct.unpack_from("!H", payload, 2)[0]

    return Packet(src_ip, dst_ip, proto, dport, is_syn)


class PacketBuffer:
    """Thread-safe ring buffer for captured packets."""

    def __init__(self):
        self._lock = threading.Lock()
        self._pkts: list[Packet] = []

    def put(self, pkt: Packet):
        with self._lock:
            self._pkts.append(pkt)

    def drain(self) -> list[Packet]:
        with self._lock:
            out, self._pkts = self._pkts, []
        return out


class Sniffer(threading.Thread):
    """
    Reads raw frames from an AF_PACKET socket in a daemon thread.
    Requires root / CAP_NET_RAW.
    """

    def __init__(self, buf: PacketBuffer, iface: str):
        super().__init__(daemon=True, name="sniffer")
        self._buf   = buf
        self._iface = iface
        self._stop  = threading.Event()
        self._sock  = None

    def run(self):
        try:
            self._sock = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(ETH_P_ALL)
            )
            self._sock.bind((self._iface, 0))
            self._sock.settimeout(1.0)
            log.info("Sniffer listening on interface: %s", self._iface)
        except PermissionError:
            log.critical(
                "Permission denied. Run with:  sudo python3 ids_main.py"
            )
            os._exit(1)
        except OSError as e:
            log.critical("Cannot open socket on %s: %s", self._iface, e)
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

    def stop(self):
        self._stop.set()

# ─────────────────────────────────────────────────────────────────────────────
# WINDOW STATISTICS
# ─────────────────────────────────────────────────────────────────────────────

class WindowStats:
    """Metrics computed from one WINDOW_SECONDS batch of packets."""
    __slots__ = (
        "total_rate", "syn_rate", "udp_rate", "icmp_rate",
        "tcp_count",  "syn_count", "udp_count", "icmp_count",
        "syn_ratio",
        "src_port_spread",   # dict: src_ip -> number of distinct dst ports
    )

    def __init__(self):
        self.total_rate = 0.0; self.syn_rate  = 0.0
        self.udp_rate   = 0.0; self.icmp_rate = 0.0
        self.tcp_count  = 0;   self.syn_count  = 0
        self.udp_count  = 0;   self.icmp_count = 0
        self.syn_ratio  = 0.0
        self.src_port_spread: dict[str, int] = {}


def compute_stats(packets: list[Packet], window_secs: float) -> WindowStats:
    ws  = WindowStats()
    src_ports: dict[str, set] = collections.defaultdict(set)

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

    n = len(packets)
    ws.total_rate = n              / window_secs
    ws.syn_rate   = ws.syn_count   / window_secs
    ws.udp_rate   = ws.udp_count   / window_secs
    ws.icmp_rate  = ws.icmp_count  / window_secs
    ws.syn_ratio  = ws.syn_count / ws.tcp_count if ws.tcp_count > 0 else 0.0
    ws.src_port_spread = {ip: len(ports) for ip, ports in src_ports.items()}

    return ws

# ─────────────────────────────────────────────────────────────────────────────
# ADAPTIVE BASELINE
# ─────────────────────────────────────────────────────────────────────────────

class Baseline:
    """
    Collects p99 peaks over BASELINE_SECONDS and sets detection thresholds.
    Thresholds = max(absolute_floor, p99_peak × THRESHOLD_MULTIPLIER)
    """

    def __init__(self):
        self._samples: dict[str, list[float]] = {
            "total": [], "syn": [], "udp": [], "icmp": []
        }
        self.thr_total = TOTAL_FLOOR
        self.thr_syn   = SYN_FLOOR
        self.thr_udp   = UDP_FLOOR
        self.thr_icmp  = ICMP_FLOOR

    def record(self, ws: WindowStats):
        self._samples["total"].append(ws.total_rate)
        self._samples["syn"].append(ws.syn_rate)
        self._samples["udp"].append(ws.udp_rate)
        self._samples["icmp"].append(ws.icmp_rate)

    @staticmethod
    def _p99(vals: list) -> float:
        if not vals:
            return 0.0
        s = sorted(vals)
        return s[max(0, int(len(s) * 0.99) - 1)]

    def finalise(self):
        p_total = self._p99(self._samples["total"])
        p_syn   = self._p99(self._samples["syn"])
        p_udp   = self._p99(self._samples["udp"])
        p_icmp  = self._p99(self._samples["icmp"])

        self.thr_total = max(TOTAL_FLOOR, p_total * THRESHOLD_MULTIPLIER)
        self.thr_syn   = max(SYN_FLOOR,   p_syn   * THRESHOLD_MULTIPLIER)
        self.thr_udp   = max(UDP_FLOOR,   p_udp   * THRESHOLD_MULTIPLIER)
        self.thr_icmp  = max(ICMP_FLOOR,  p_icmp  * THRESHOLD_MULTIPLIER)

        log.info(
            "Baseline done. Thresholds →  "
            "total=%.0f/s  syn=%.0f/s  udp=%.0f/s  icmp=%.0f/s",
            self.thr_total, self.thr_syn, self.thr_udp, self.thr_icmp,
        )
        log.info(
            "Observed p99 peaks →  "
            "total=%.1f/s  syn=%.1f/s  udp=%.1f/s  icmp=%.1f/s",
            p_total, p_syn, p_udp, p_icmp,
        )
        write_alert(
            "IDS entered DETECTION mode",
            f"thr_total={self.thr_total:.0f}/s "
            f"thr_syn={self.thr_syn:.0f}/s "
            f"thr_udp={self.thr_udp:.0f}/s "
            f"thr_icmp={self.thr_icmp:.0f}/s"
        )

# ─────────────────────────────────────────────────────────────────────────────
# RULE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class RuleEngine:
    """
    Evaluates 5 rules each window. Each rule has its own streak counter
    and cooldown timer — they are completely independent.
    """

    def __init__(self, baseline: Baseline):
        self._b          = baseline
        self._streak:     dict[str, int]   = collections.defaultdict(int)
        self._last_alert: dict[str, float] = collections.defaultdict(float)

    def _arm(self, rule: str, kind: str, detail: str):
        """Increment streak; write alert only when confirmation + cooldown pass."""
        self._streak[rule] += 1
        if self._streak[rule] < CONFIRM_WINDOWS:
            log.debug("[SUSPECT] %-20s  streak=%d/%d",
                      rule, self._streak[rule], CONFIRM_WINDOWS)
            return
        now  = time.monotonic()
        wait = COOLDOWN_SECS - (now - self._last_alert[rule])
        if wait > 0:
            log.debug("[COOLDOWN] %-20s  %.0fs remaining", rule, wait)
            return
        self._last_alert[rule] = now
        self._streak[rule]     = 0
        write_alert(kind, detail)

    def _clear(self, rule: str):
        if self._streak[rule]:
            log.debug("[CLEAR] %-20s  streak reset", rule)
            self._streak[rule] = 0

    def evaluate(self, ws: WindowStats):
        b = self._b
        proto_fired = False

        # ── Rule 1: SYN flood ────────────────────────────────────────────────
        if ws.syn_rate > b.thr_syn and ws.syn_ratio > SYN_RATIO_MIN:
            self._arm(
                "syn_flood", "SYN flood",
                f"syn={ws.syn_rate:.0f}/s (thr={b.thr_syn:.0f}) "
                f"ratio={ws.syn_ratio:.0%} tcp={ws.tcp_count} syn={ws.syn_count}"
            )
            proto_fired = True
        else:
            self._clear("syn_flood")

        # ── Rule 2: UDP flood ────────────────────────────────────────────────
        if ws.udp_rate > b.thr_udp:
            self._arm(
                "udp_flood", "UDP flood",
                f"udp={ws.udp_rate:.0f}/s (thr={b.thr_udp:.0f}) pkts={ws.udp_count}"
            )
            proto_fired = True
        else:
            self._clear("udp_flood")

        # ── Rule 3: ICMP flood ───────────────────────────────────────────────
        if ws.icmp_rate > b.thr_icmp:
            self._arm(
                "icmp_flood", "ICMP flood",
                f"icmp={ws.icmp_rate:.0f}/s (thr={b.thr_icmp:.0f}) pkts={ws.icmp_count}"
            )
            proto_fired = True
        else:
            self._clear("icmp_flood")

        # ── Rule 4: Volumetric DoS (catch-all, no duplicate) ────────────────
        if ws.total_rate > b.thr_total and not proto_fired:
            self._arm(
                "vol_flood", "Volumetric DoS",
                f"rate={ws.total_rate:.0f}/s (thr={b.thr_total:.0f}) "
                f"tcp={ws.tcp_count} udp={ws.udp_count} icmp={ws.icmp_count}"
            )
        else:
            self._clear("vol_flood")

        # ── Rule 5: Port scan ────────────────────────────────────────────────
        active_scanners: set[str] = set()
        for ip, spread in ws.src_port_spread.items():
            if spread >= PORT_SCAN_THRESHOLD:
                key = f"scan_{ip}"
                active_scanners.add(key)
                self._arm(
                    key, "Port scan",
                    f"src={ip} ports={spread} (thr={PORT_SCAN_THRESHOLD})"
                )
        for key in list(self._streak):
            if key.startswith("scan_") and key not in active_scanners:
                self._clear(key)

        log.debug(
            "[WIN] total=%.0f syn=%.0f(%.0f%%) udp=%.0f icmp=%.0f spread_max=%d",
            ws.total_rate, ws.syn_rate, ws.syn_ratio * 100,
            ws.udp_rate, ws.icmp_rate,
            max(ws.src_port_spread.values()) if ws.src_port_spread else 0,
        )

# ─────────────────────────────────────────────────────────────────────────────
# IDS MAIN CLASS
# ─────────────────────────────────────────────────────────────────────────────

class IDS:
    def __init__(self):
        iface        = get_interface()
        self._buf    = PacketBuffer()
        self._sniffer = Sniffer(self._buf, iface)
        self._baseline = Baseline()
        self._engine   = None

        self._phase       = "baseline"
        self._phase_start = time.monotonic()
        self._windows     = 0

        self._running = True
        signal.signal(signal.SIGTERM, self._stop_signal)
        signal.signal(signal.SIGINT,  self._stop_signal)

    def _stop_signal(self, sig, _):
        log.info("Signal received — shutting down cleanly.")
        self._running = False

    def run(self):
        log.info(
            "IDS starting  |  baseline=%ds  window=%ds  "
            "multiplier=%dx  confirm=%d  cooldown=%ds",
            BASELINE_SECONDS, WINDOW_SECONDS,
            THRESHOLD_MULTIPLIER, CONFIRM_WINDOWS, COOLDOWN_SECS,
        )
        write_alert(
            "IDS started",
            f"baseline={BASELINE_SECONDS}s window={WINDOW_SECONDS}s "
            f"multiplier={THRESHOLD_MULTIPLIER}x"
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

                # ── BASELINE PHASE ────────────────────────────────────────────
                if self._phase == "baseline":
                    self._baseline.record(ws)
                    elapsed   = time.monotonic() - self._phase_start
                    remaining = max(0, BASELINE_SECONDS - elapsed)

                    log.info(
                        "[BASELINE  %3.0fs left]  "
                        "pkts=%4d  total=%.0f/s  syn=%.0f/s  "
                        "udp=%.0f/s  icmp=%.0f/s",
                        remaining, len(pkts),
                        ws.total_rate, ws.syn_rate,
                        ws.udp_rate,   ws.icmp_rate,
                    )

                    if elapsed >= BASELINE_SECONDS:
                        self._baseline.finalise()
                        self._engine = RuleEngine(self._baseline)
                        self._phase  = "detecting"
                        log.info("Detection ARMED. Monitoring for attacks.")

                # ── DETECTION PHASE ───────────────────────────────────────────
                else:
                    log.info(
                        "[DETECTING]           "
                        "pkts=%4d  total=%.0f/s  syn=%.0f/s  "
                        "udp=%.0f/s  icmp=%.0f/s",
                        len(pkts),
                        ws.total_rate, ws.syn_rate,
                        ws.udp_rate,   ws.icmp_rate,
                    )
                    self._engine.evaluate(ws)

        finally:
            self._sniffer.stop()
            log.info("IDS stopped. Total windows: %d", self._windows)
            write_alert("IDS stopped", f"windows={self._windows}")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    IDS().run()
