"""
ids_main.py — Rule-Based Intrusion Detection System with Adaptive Baselines
============================================================================

WHY THIS APPROACH
-----------------
The previous Isolation Forest design treated ANY statistical outlier as a
potential attack. On a real LAN, normal traffic is highly variable — file
downloads, video calls, mDNS storms, NTP syncs, backup jobs — all produce
"outlier" traffic that is completely legitimate. A general-purpose anomaly
detector cannot tell the difference, so false-positive rates are always high.

This IDS instead does two things:

  1. RULE-BASED SIGNATURES for known DoS/attack patterns.
     Every rule checks a specific, meaningful metric that a real attack
     produces at a level NO normal LAN activity ever reaches:
       - SYN flood:        hundreds of SYN packets with FEW completions
       - UDP flood:        extreme UDP packet rate sustained over time
       - ICMP flood:       ICMP volume that only a ping-of-death/smurf produces
       - Port scan:        one source touching many ports rapidly
       - Volumetric DoS:   raw packet rate at an extreme multiple of normal

  2. ADAPTIVE THRESHOLD LEARNING for rate-based rules.
     During a 3-minute quiet baseline, the IDS measures the actual normal
     peaks for packet rate, SYN rate, UDP rate, and ICMP rate on YOUR
     specific network. Detection thresholds are then set to a multiple of
     those measured peaks (THRESHOLD_MULTIPLIER, default 8x).
     This means a network that legitimately sees 200 pkt/s will require
     1600 pkt/s to alert, while a quieter network will have a tighter bound.
     Normal traffic — however bursty — will never reach 8x its own peak.

WHAT TRIGGERS AN ALERT (the only things that do)
-------------------------------------------------
  Rule 1 — SYN FLOOD
      syn_rate > baseline_syn_peak x 8   AND   syn_ratio > 0.70
      (many SYNs and most are not completing handshakes)

  Rule 2 — UDP FLOOD
      udp_rate > baseline_udp_peak x 8
      (normal UDP: DNS, NTP, mDNS — combined rarely exceeds 50/s)

  Rule 3 — ICMP FLOOD
      icmp_rate > max(50/s floor, baseline_icmp_peak x 8)
      (no normal network sends 50 ICMP pkt/s)

  Rule 4 — VOLUMETRIC DoS  (catch-all for raw packet floods)
      total_rate > baseline_rate_peak x 8
      (only fires when NOT already covered by rules 1-3)

  Rule 5 — PORT SCAN
      single source IP touches >= 50 distinct dst ports in one window

Each rule also requires CONFIRM_WINDOWS consecutive triggered windows
before alerting (prevents single-burst false positives), and COOLDOWN_SECS
between repeat alerts for the same rule so one attack = one alert.

INTEGRATION CONTRACT
--------------------
  - Run as:       python ids_main.py    (requires root / sudo for capture)
  - Alert file:   alerts.log   — appended, one line per alert
  - Alert format: [YYYY-MM-DD HH:MM:SS] ALERT: <kind> | <detail>
  - Log file:     ids.log      — rotating, 5 MB x 2 backups
  - Stop with:    Ctrl-C or SIGTERM
"""

import sys
import time
import signal
import logging
import threading
import collections
from datetime import datetime
from logging.handlers import RotatingFileHandler

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf as scapy_conf
except ImportError:
    sys.exit("ERROR: scapy is required — pip install scapy")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

INTERFACE            = None  # None = Scapy default; set e.g. "eth0" / "en0"
WINDOW_SECONDS       = 3     # measurement window length in seconds

# Baseline: observe this many seconds of quiet normal traffic before arming
BASELINE_SECONDS     = 180   # 3 minutes — covers LAN background noise cycles

# Alert fires when a metric exceeds this multiple of the observed normal peak.
# 8x means traffic must be EIGHT TIMES your own measured normal peak.
# Lower to 5 for faster detection, raise to 10 for near-zero false positives.
THRESHOLD_MULTIPLIER = 8

# Absolute minimum floors — fire regardless of baseline because NO legitimate
# LAN traffic ever reaches these levels.
SYN_RATE_FLOOR   = 100   # SYN pkt/s  (normal apps: < 10/s)
UDP_RATE_FLOOR   = 500   # UDP pkt/s  (DNS+NTP+mDNS combined: < 50/s)
ICMP_RATE_FLOOR  = 50    # ICMP pkt/s (normal: near 0)
RATE_FLOOR       = 2000  # total pkt/s absolute floor

# SYN ratio: fraction of TCP packets that are SYNs indicating handshakes
# are not completing — hallmark of a SYN flood. 0.70 = 70%.
SYN_RATIO_THRESHOLD  = 0.70

# Port scan: source IP touching this many distinct dst ports in one window
PORT_SCAN_THRESHOLD  = 50

# Confirmation windows before alerting (prevents single-burst false positives)
CONFIRM_WINDOWS      = 2    # 2 x 3s = 6 seconds of sustained behaviour

# Cooldown: suppress repeat alerts for the same rule for this many seconds
COOLDOWN_SECS        = 90

ALERT_LOG = "alerts.log"
INFO_LOG  = "ids.log"


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging():
    fmt  = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s",
                              datefmt="%Y-%m-%d %H:%M:%S")
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
log = logging.getLogger(__name__)


def _write_alert(kind: str, detail: str):
    """Append one alert line to alerts.log in the standard format."""
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] ALERT: {kind} | {detail}"
    try:
        with open(ALERT_LOG, "a") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        log.error("Cannot write alert: %s", exc)
    log.warning("ALERT: %s | %s", kind, detail)


# ─────────────────────────────────────────────────────────────────────────────
# PACKET BUFFER  (thread-safe)
# ─────────────────────────────────────────────────────────────────────────────

class PacketBuffer:
    def __init__(self):
        self._lock = threading.Lock()
        self._pkts = []

    def add(self, pkt):
        with self._lock:
            self._pkts.append(pkt)

    def drain(self) -> list:
        with self._lock:
            out, self._pkts = self._pkts, []
        return out


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

class WindowStats:
    """All measurements extracted from one time window of packets."""
    __slots__ = (
        "total_pkts", "window_secs",
        "total_rate",
        "syn_count",  "syn_rate",
        "tcp_count",  "tcp_rate",
        "udp_count",  "udp_rate",
        "icmp_count", "icmp_rate",
        "syn_ratio",
        "src_port_spread",   # dict[str, int]: src_ip -> distinct dst port count
    )

    def __init__(self):
        self.total_pkts = 0
        self.window_secs = 1
        self.total_rate = 0.0
        self.syn_count  = 0;  self.syn_rate  = 0.0
        self.tcp_count  = 0;  self.tcp_rate  = 0.0
        self.udp_count  = 0;  self.udp_rate  = 0.0
        self.icmp_count = 0;  self.icmp_rate = 0.0
        self.syn_ratio  = 0.0
        self.src_port_spread = {}


def extract(packets: list, window_secs: float) -> WindowStats:
    ws = WindowStats()
    ws.window_secs = window_secs

    src_ports: dict = collections.defaultdict(set)

    for pkt in packets:
        if IP not in pkt:
            continue
        ws.total_pkts += 1
        src = pkt[IP].src

        if TCP in pkt:
            ws.tcp_count += 1
            src_ports[src].add(pkt[TCP].dport)
            if pkt[TCP].flags & 0x02:   # SYN bit
                ws.syn_count += 1
        elif UDP in pkt:
            ws.udp_count += 1
            src_ports[src].add(pkt[UDP].dport)
        elif ICMP in pkt:
            ws.icmp_count += 1

    w = window_secs
    ws.total_rate = ws.total_pkts / w
    ws.syn_rate   = ws.syn_count  / w
    ws.tcp_rate   = ws.tcp_count  / w
    ws.udp_rate   = ws.udp_count  / w
    ws.icmp_rate  = ws.icmp_count / w

    ws.syn_ratio  = (ws.syn_count / ws.tcp_count) if ws.tcp_count > 0 else 0.0
    ws.src_port_spread = {ip: len(ports) for ip, ports in src_ports.items()}

    return ws


# ─────────────────────────────────────────────────────────────────────────────
# ADAPTIVE BASELINE
# ─────────────────────────────────────────────────────────────────────────────

class Baseline:
    """
    Collects BASELINE_SECONDS of traffic samples and computes the 99th-
    percentile peak for each rate metric.  Using p99 rather than the absolute
    maximum prevents a single momentary burst during baseline from setting
    a threshold too high and hiding real attacks.

    Thresholds = max(absolute_floor, p99_peak x THRESHOLD_MULTIPLIER)
    """

    def __init__(self):
        self._samples = {
            "total_rate": [],
            "syn_rate":   [],
            "udp_rate":   [],
            "icmp_rate":  [],
        }
        self.ready = False
        # Final thresholds — initialised to floors, replaced after finalise()
        self.thr_total = RATE_FLOOR
        self.thr_syn   = SYN_RATE_FLOOR
        self.thr_udp   = UDP_RATE_FLOOR
        self.thr_icmp  = ICMP_RATE_FLOOR

    def record(self, ws: WindowStats):
        self._samples["total_rate"].append(ws.total_rate)
        self._samples["syn_rate"].append(ws.syn_rate)
        self._samples["udp_rate"].append(ws.udp_rate)
        self._samples["icmp_rate"].append(ws.icmp_rate)

    @staticmethod
    def _p99(values: list) -> float:
        if not values:
            return 0.0
        s   = sorted(values)
        idx = max(0, int(len(s) * 0.99) - 1)
        return s[idx]

    def finalise(self):
        peak_total = self._p99(self._samples["total_rate"])
        peak_syn   = self._p99(self._samples["syn_rate"])
        peak_udp   = self._p99(self._samples["udp_rate"])
        peak_icmp  = self._p99(self._samples["icmp_rate"])

        self.thr_total = max(RATE_FLOOR,      peak_total * THRESHOLD_MULTIPLIER)
        self.thr_syn   = max(SYN_RATE_FLOOR,  peak_syn   * THRESHOLD_MULTIPLIER)
        self.thr_udp   = max(UDP_RATE_FLOOR,  peak_udp   * THRESHOLD_MULTIPLIER)
        self.thr_icmp  = max(ICMP_RATE_FLOOR, peak_icmp  * THRESHOLD_MULTIPLIER)

        self.ready = True

        log.info(
            "Baseline finalised — thresholds: "
            "total=%.0f/s  syn=%.0f/s  udp=%.0f/s  icmp=%.0f/s",
            self.thr_total, self.thr_syn, self.thr_udp, self.thr_icmp,
        )
        log.info(
            "Observed peaks (p99): "
            "total=%.1f/s  syn=%.1f/s  udp=%.1f/s  icmp=%.1f/s",
            peak_total, peak_syn, peak_udp, peak_icmp,
        )
        _write_alert(
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
    Evaluates five rules per window.  Each rule has its own streak counter
    and cooldown timer so rules don't interfere with each other.
    """

    def __init__(self, baseline: Baseline):
        self._b          = baseline
        self._streak     = collections.defaultdict(int)
        self._last_alert = collections.defaultdict(float)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _trigger(self, rule: str, kind: str, detail: str):
        """Increment streak; alert only when confirmation + cooldown pass."""
        self._streak[rule] += 1
        streak = self._streak[rule]

        if streak < CONFIRM_WINDOWS:
            log.debug("[SUSPECT:%s] streak=%d/%d", rule, streak, CONFIRM_WINDOWS)
            return

        now = time.monotonic()
        wait = COOLDOWN_SECS - (now - self._last_alert[rule])
        if wait > 0:
            log.debug("[SUPPRESS:%s] cooldown %.0fs remaining", rule, wait)
            return

        # All conditions met — fire alert and reset
        self._last_alert[rule] = now
        self._streak[rule]     = 0
        _write_alert(kind, detail)

    def _clear(self, rule: str):
        if self._streak[rule] > 0:
            log.debug("[CLEAR:%s] streak reset (was %d)", rule, self._streak[rule])
            self._streak[rule] = 0

    # ── Rules ─────────────────────────────────────────────────────────────────

    def evaluate(self, ws: WindowStats):
        b = self._b

        # Track which protocol rules fired to avoid duplicate vol_flood alert
        proto_fired = False

        # Rule 1 — SYN Flood
        # High SYN rate AND most TCP are SYNs (handshakes not completing)
        if ws.syn_rate > b.thr_syn and ws.syn_ratio > SYN_RATIO_THRESHOLD:
            self._trigger(
                "syn_flood",
                "SYN flood / port scan",
                f"syn_rate={ws.syn_rate:.0f}/s "
                f"(threshold={b.thr_syn:.0f}/s) "
                f"syn_ratio={ws.syn_ratio:.0%} "
                f"syn={ws.syn_count} tcp={ws.tcp_count}"
            )
            proto_fired = True
        else:
            self._clear("syn_flood")

        # Rule 2 — UDP Flood
        if ws.udp_rate > b.thr_udp:
            self._trigger(
                "udp_flood",
                "UDP flood",
                f"udp_rate={ws.udp_rate:.0f}/s "
                f"(threshold={b.thr_udp:.0f}/s) "
                f"udp_pkts={ws.udp_count}"
            )
            proto_fired = True
        else:
            self._clear("udp_flood")

        # Rule 3 — ICMP Flood
        if ws.icmp_rate > b.thr_icmp:
            self._trigger(
                "icmp_flood",
                "ICMP flood",
                f"icmp_rate={ws.icmp_rate:.0f}/s "
                f"(threshold={b.thr_icmp:.0f}/s) "
                f"icmp_pkts={ws.icmp_count}"
            )
            proto_fired = True
        else:
            self._clear("icmp_flood")

        # Rule 4 — Volumetric DoS (raw rate, only when not already covered)
        if ws.total_rate > b.thr_total and not proto_fired:
            self._trigger(
                "vol_flood",
                "Volumetric DoS",
                f"rate={ws.total_rate:.0f}/s "
                f"(threshold={b.thr_total:.0f}/s) "
                f"tcp={ws.tcp_count} udp={ws.udp_count} icmp={ws.icmp_count}"
            )
        else:
            self._clear("vol_flood")

        # Rule 5 — Port Scan (per-source-IP)
        scanning_now = set()
        for ip, spread in ws.src_port_spread.items():
            if spread >= PORT_SCAN_THRESHOLD:
                key = f"portscan_{ip}"
                scanning_now.add(key)
                self._trigger(
                    key,
                    "Port scan",
                    f"src={ip} ports_in_window={spread} "
                    f"(threshold={PORT_SCAN_THRESHOLD})"
                )

        # Clear streaks for IPs that stopped scanning
        for key in list(self._streak):
            if key.startswith("portscan_") and key not in scanning_now:
                self._clear(key)

        # Per-window debug line (written to ids.log, not stdout)
        log.debug(
            "[WIN] total=%.0f/s syn=%.0f/s(%.0f%%) udp=%.0f/s icmp=%.0f/s"
            " max_spread=%d",
            ws.total_rate, ws.syn_rate, ws.syn_ratio * 100,
            ws.udp_rate, ws.icmp_rate,
            max(ws.src_port_spread.values()) if ws.src_port_spread else 0,
        )


# ─────────────────────────────────────────────────────────────────────────────
# SNIFFER THREAD
# ─────────────────────────────────────────────────────────────────────────────

class Sniffer(threading.Thread):
    def __init__(self, buf: PacketBuffer, iface=None):
        super().__init__(daemon=True, name="sniffer")
        self._buf   = buf
        self._iface = iface
        self._stop  = threading.Event()
        scapy_conf.verb = 0

    def _cb(self, pkt):
        if not self._stop.is_set():
            self._buf.add(pkt)

    def run(self):
        log.info("Sniffer started — interface: %s", self._iface or "default")
        try:
            sniff(
                iface       = self._iface,
                prn         = self._cb,
                store       = False,
                stop_filter = lambda _: self._stop.is_set(),
            )
        except PermissionError:
            log.critical(
                "Packet capture requires root privileges — "
                "re-run with:  sudo python ids_main.py"
            )
            sys.exit(1)
        except Exception as exc:
            log.critical("Sniffer crashed: %s", exc, exc_info=True)
            sys.exit(1)

    def stop(self):
        self._stop.set()


# ─────────────────────────────────────────────────────────────────────────────
# IDS ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class IDS:
    def __init__(self):
        self._buf      = PacketBuffer()
        self._sniffer  = Sniffer(self._buf, iface=INTERFACE)
        self._baseline = Baseline()
        self._engine   = None       # RuleEngine created after baseline ready

        self._phase       = "baseline"
        self._phase_start = time.monotonic()
        self._windows     = 0

        self._running = True
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT,  self._handle_signal)

    def _handle_signal(self, sig, _frame):
        log.info("Signal %s — stopping.", signal.Signals(sig).name)
        self._running = False

    def run(self):
        log.info(
            "IDS starting — baseline %ds | window %ds | "
            "multiplier %dx | confirm %d | cooldown %ds",
            BASELINE_SECONDS, WINDOW_SECONDS,
            THRESHOLD_MULTIPLIER, CONFIRM_WINDOWS, COOLDOWN_SECS,
        )
        _write_alert(
            "IDS started",
            f"baseline={BASELINE_SECONDS}s  window={WINDOW_SECONDS}s  "
            f"multiplier={THRESHOLD_MULTIPLIER}x  confirm={CONFIRM_WINDOWS}"
        )
        self._sniffer.start()

        try:
            while self._running:
                time.sleep(WINDOW_SECONDS)
                if not self._running:
                    break

                packets = self._buf.drain()
                ws      = extract(packets, WINDOW_SECONDS)
                self._windows += 1

                # ── BASELINE ──────────────────────────────────────────────────
                if self._phase == "baseline":
                    self._baseline.record(ws)
                    elapsed   = time.monotonic() - self._phase_start
                    remaining = max(0, BASELINE_SECONDS - elapsed)

                    log.info(
                        "[BASELINE %.0fs left] "
                        "rate=%.0f/s  syn=%.0f/s  udp=%.0f/s  icmp=%.0f/s",
                        remaining,
                        ws.total_rate, ws.syn_rate, ws.udp_rate, ws.icmp_rate,
                    )

                    if elapsed >= BASELINE_SECONDS:
                        self._baseline.finalise()
                        self._engine = RuleEngine(self._baseline)
                        self._phase  = "detecting"
                        log.info("Rules armed. Watching for attacks.")

                # ── DETECTION ─────────────────────────────────────────────────
                else:
                    self._engine.evaluate(ws)

        finally:
            self._sniffer.stop()
            log.info("IDS stopped after %d windows.", self._windows)
            _write_alert("IDS stopped", f"windows={self._windows}")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    IDS().run()
