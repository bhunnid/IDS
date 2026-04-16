"""
ids_main.py — Lightweight Anomaly-Based Intrusion Detection System
===================================================================

HOW IT WORKS
------------
1. CAPTURE: Scapy sniffs all packets on the default network interface in a
   background thread, storing them in a thread-safe rolling buffer.

2. FEATURE EXTRACTION: Every WINDOW_SECONDS (5 s), the main loop drains the
   buffer and computes a lightweight feature vector for that window:
       [packet_rate, tcp_count, udp_count, icmp_count, avg_pkt_size,
        syn_count, unique_src_ips, unique_dst_ports]

3. TRAINING PHASE (first TRAIN_SECONDS, default 300 s / 5 min): Feature
   vectors are collected but no alerts are raised. A longer baseline is
   critical on a private LAN — it must cover bursts from mDNS, ARP, NTP,
   DHCP renewals, backup jobs, etc. so they are learned as "normal".

4. DETECTION PHASE: An Isolation Forest is trained on the baseline. Every new
   feature vector is scored. Isolation Forest marks a sample as anomalous when
   it is easily isolated (short average path length in random trees). The raw
   model flag is NOT sufficient to fire an alert — three additional gates must
   all pass:

   Gate 1 — SCORE DEPTH: the anomaly score must be below SCORE_THRESHOLD
            (default -0.15). Scores just below 0.0 are borderline noise;
            truly anomalous traffic scores well below -0.1.

   Gate 2 — CONFIRMATION STREAK: the window must be anomalous for
            CONFIRM_WINDOWS consecutive windows (default 2) before an alert
            fires. A single-window spike (e.g. a large download, a brief
            broadcast storm) is suppressed.

   Gate 3 — ALERT COOLDOWN: once an alert fires, no further alert fires for
            ALERT_COOLDOWN_SECONDS (default 60 s). This prevents one attack
            event from generating dozens of repeated lines.

5. ADAPTIVE RE-TRAINING: The model is periodically re-trained on a rolling
   window of recent *normal* windows so it adapts to legitimate traffic shifts
   (e.g. a cron job, a video call) without requiring a restart.

FALSE-POSITIVE TUNING GUIDE
----------------------------
Still too noisy?   Lower SCORE_THRESHOLD (e.g. -0.20) or raise CONFIRM_WINDOWS
                   to 3.  Extend TRAIN_SECONDS to 600 s.
Missing real attacks? Raise SCORE_THRESHOLD toward -0.10 or lower
                   CONFIRM_WINDOWS to 1.

RESOURCE USAGE
--------------
- One background sniffer thread (Scapy) — woken only on packet arrival.
- One main loop sleeping WINDOW_SECONDS between iterations.
- Isolation Forest with 100 estimators on ≤3600 samples — negligible RAM/CPU.

INTEGRATION CONTRACT
--------------------
- Launchable as:  python ids_main.py
- Alert output:   alerts.log  (one line per alert, appended)
- Alert format:   [YYYY-MM-DD HH:MM:SS] ALERT: <description>
- Info/debug:     ids.log     (rotation at 5 MB, 2 backups)
- Terminate with: Ctrl-C or SIGTERM — shuts down cleanly.
"""

# ── Standard library ────────────────────────────────────────────────────────
import sys
import time
import signal
import logging
import threading
import collections
from datetime import datetime
from logging.handlers import RotatingFileHandler

# ── Third-party ──────────────────────────────────────────────────────────────
try:
    import numpy as np
except ImportError:
    sys.exit("ERROR: numpy is required.  pip install numpy")

try:
    from sklearn.ensemble import IsolationForest
except ImportError:
    sys.exit("ERROR: scikit-learn is required.  pip install scikit-learn")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf as scapy_conf
except ImportError:
    sys.exit("ERROR: scapy is required.  pip install scapy")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  (tweak these values — no external config file needed)
# ─────────────────────────────────────────────────────────────────────────────

# ── Capture / windowing ──────────────────────────────────────────────────────
WINDOW_SECONDS        = 5        # seconds per feature window (longer = smoother)
INTERFACE             = None     # None → Scapy default; or e.g. "eth0" / "en0"

# ── Baseline training ────────────────────────────────────────────────────────
TRAIN_SECONDS         = 300      # 5 minutes of baseline (cover normal LAN noise)
MIN_TRAIN_SAMPLES     = 30       # don't train until we have this many windows

# ── Isolation Forest ─────────────────────────────────────────────────────────
IF_ESTIMATORS         = 100
# contamination: fraction of training data expected to be anomalous.
# 0.01 = 1% → model is conservative, only flags clear outliers.
# Raise toward 0.05 only if you have reason to believe training traffic
# included some genuinely bad traffic.
IF_CONTAMINATION      = "auto"

# ── Alert suppression — the three false-positive gates ──────────────────────
# Gate 1: minimum anomaly score depth to even consider alerting.
# IsolationForest scores: 0.0 = boundary, -1.0 = most anomalous.
# -0.15 means the window must be clearly in anomaly territory, not borderline.
SCORE_THRESHOLD       = -0.10

# Gate 2: how many *consecutive* anomalous windows before an alert fires.
# 2 windows × 5 s = 10 s of sustained anomaly required.
CONFIRM_WINDOWS       = 2

# Gate 3: minimum seconds between any two alerts (suppresses alert storms).
ALERT_COOLDOWN_SECS   = 60

# ── Adaptive re-training ─────────────────────────────────────────────────────
RETRAIN_EVERY_WINDOWS = 180      # re-train every N normal windows (~15 min)
NORMAL_HISTORY_SIZE   = 3600     # max normal windows kept for rolling re-train

# ── File paths ───────────────────────────────────────────────────────────────
ALERT_LOG             = "alerts.log"
INFO_LOG              = "ids.log"

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging():
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s",
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


def _write_alert(msg: str):
    """Append a timestamped alert line to alerts.log and the info log."""
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] ALERT: {msg}"
    try:
        with open(ALERT_LOG, "a") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        log.error("Cannot write to %s: %s", ALERT_LOG, exc)
    log.warning("ALERT: %s", msg)


# ─────────────────────────────────────────────────────────────────────────────
# PACKET BUFFER  (thread-safe)
# ─────────────────────────────────────────────────────────────────────────────

class PacketBuffer:
    """Thread-safe packet accumulator fed by the sniffer thread."""

    def __init__(self):
        self._lock   = threading.Lock()
        self._buffer = []

    def add(self, pkt):
        with self._lock:
            self._buffer.append(pkt)

    def drain(self) -> list:
        """Atomically return all buffered packets and reset the buffer."""
        with self._lock:
            pkts, self._buffer = self._buffer, []
        return pkts


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "packet_rate",       # packets / second
    "tcp_count",         # raw TCP packet count in window
    "udp_count",
    "icmp_count",
    "avg_pkt_size",      # mean IP total-length (bytes)
    "syn_count",         # TCP SYN flag count (new connection attempts)
    "unique_src_ips",    # distinct source IPs seen
    "unique_dst_ports",  # distinct destination ports seen
]


def extract_features(packets: list, window_secs: float) -> np.ndarray:
    """
    Derive a feature vector from packets captured in one time window.
    Returns shape (8,) float64 array.
    """
    n = len(packets)
    if n == 0:
        return np.zeros(len(FEATURE_NAMES), dtype=float)

    tcp = udp = icmp = syn = 0
    pkt_sizes  = []
    src_ips    = set()
    dst_ports  = set()

    for pkt in packets:
        if IP not in pkt:
            continue
        ip_layer = pkt[IP]
        pkt_sizes.append(ip_layer.len)
        src_ips.add(ip_layer.src)

        if TCP in pkt:
            tcp += 1
            tcp_layer = pkt[TCP]
            dst_ports.add(tcp_layer.dport)
            if tcp_layer.flags & 0x02:   # SYN flag bit
                syn += 1
        elif UDP in pkt:
            udp += 1
            dst_ports.add(pkt[UDP].dport)
        elif ICMP in pkt:
            icmp += 1

    avg_size = float(np.mean(pkt_sizes)) if pkt_sizes else 0.0

    return np.array([
        n / window_secs,
        float(tcp),
        float(udp),
        float(icmp),
        avg_size,
        float(syn),
        float(len(src_ips)),
        float(len(dst_ports)),
    ], dtype=float)


# ─────────────────────────────────────────────────────────────────────────────
# ANOMALY DETECTOR
# ─────────────────────────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Wraps IsolationForest.  Returns a raw (is_flagged, score) tuple.
    The IDS layer applies the confirmation + cooldown gates on top.
    """

    def __init__(self):
        self._model: IsolationForest | None = None
        self._lock  = threading.Lock()

    def train(self, X: np.ndarray):
        model = IsolationForest(
            n_estimators  = IF_ESTIMATORS,
            contamination = IF_CONTAMINATION,
            random_state  = 42,
            n_jobs        = 1,
        )
        model.fit(X)
        with self._lock:
            self._model = model
        log.info("Model trained on %d windows (contamination=%s).",
                 len(X), IF_CONTAMINATION)

    def score(self, features: np.ndarray) -> tuple[bool, float]:
        """
        Returns (model_flagged: bool, decision_score: float).
        decision_score < 0 → anomaly territory; closer to -1 → more extreme.
        """
        with self._lock:
            if self._model is None:
                return False, 0.0
            x     = features.reshape(1, -1)
            pred  = self._model.predict(x)[0]          # 1 = normal, -1 = anomaly
            sc    = self._model.decision_function(x)[0]
        return (pred == -1), float(sc)


# ─────────────────────────────────────────────────────────────────────────────
# SNIFFER THREAD
# ─────────────────────────────────────────────────────────────────────────────

class Sniffer(threading.Thread):
    """Daemon thread that feeds raw packets into a PacketBuffer."""

    def __init__(self, buffer: PacketBuffer, iface=None):
        super().__init__(daemon=True, name="sniffer")
        self._buf   = buffer
        self._iface = iface
        self._stop  = threading.Event()
        scapy_conf.verb = 0   # silence Scapy's own output

    def _cb(self, pkt):
        if not self._stop.is_set():
            self._buf.add(pkt)

    def run(self):
        log.info("Sniffer started on interface: %s", self._iface or "default")
        try:
            sniff(
                iface       = self._iface,
                prn         = self._cb,
                store       = False,
                stop_filter = lambda _: self._stop.is_set(),
            )
        except PermissionError:
            log.critical("Packet capture requires root/admin privileges. "
                         "Re-run with: sudo python ids_main.py")
            sys.exit(1)
        except Exception as exc:
            log.critical("Sniffer crashed: %s", exc, exc_info=True)
            sys.exit(1)

    def stop(self):
        self._stop.set()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN DETECTION LOOP
# ─────────────────────────────────────────────────────────────────────────────

class IDS:
    def __init__(self):
        self._buf      = PacketBuffer()
        self._sniffer  = Sniffer(self._buf, iface=INTERFACE)
        self._detector = AnomalyDetector()

        self._normal_history: collections.deque = collections.deque(
            maxlen=NORMAL_HISTORY_SIZE
        )
        self._training_vectors: list[np.ndarray] = []

        self._phase            = "training"
        self._phase_start      = time.monotonic()
        self._windows_since_rt = 0

        # False-positive gate state
        self._consecutive_anomalies = 0          # Gate 2 counter
        self._last_alert_time       = 0.0        # Gate 3 timestamp

        self._total_windows = 0
        self._total_alerts  = 0

        self._running = True
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT,  self._handle_signal)

    def _handle_signal(self, sig, _frame):
        log.info("Shutdown signal (%s) received.", signal.Signals(sig).name)
        self._running = False

    # ── Training → detection transition ─────────────────────────────────────

    def _enter_detection(self):
        X = np.array(self._training_vectors)
        self._detector.train(X)
        for v in self._training_vectors:
            self._normal_history.append(v)
        self._phase = "detecting"
        log.info("Switched to DETECTION mode (%d training windows).",
                 len(self._training_vectors))
        _write_alert(
            f"IDS entered DETECTION mode — "
            f"baseline={len(self._training_vectors)} windows, "
            f"score_threshold={SCORE_THRESHOLD}, "
            f"confirm_windows={CONFIRM_WINDOWS}, "
            f"cooldown={ALERT_COOLDOWN_SECS}s"
        )

    # ── Adaptive re-training on rolling normal history ───────────────────────

    def _maybe_retrain(self):
        self._windows_since_rt += 1
        if (self._windows_since_rt >= RETRAIN_EVERY_WINDOWS
                and len(self._normal_history) >= MIN_TRAIN_SAMPLES):
            X = np.array(self._normal_history)
            self._detector.train(X)
            self._windows_since_rt = 0
            log.info("Adaptive re-train: %d normal windows in history.",
                     len(self._normal_history))

    # ── Three-gate alert decision ────────────────────────────────────────────

    def _evaluate(self, features: np.ndarray, packets: list):
        """
        Apply the three false-positive suppression gates and fire an alert
        only when all three pass simultaneously.
        """
        model_flagged, score = self._detector.score(features)

        # ── Gate 1: score must be deep enough in anomaly territory ───────────
        deep_enough = model_flagged and (score <= SCORE_THRESHOLD)

        if deep_enough:
            self._consecutive_anomalies += 1
            log.debug("[SUSPECT] streak=%d  score=%.3f  rate=%.1f/s  syn=%d  "
                      "src_ips=%d  dst_ports=%d",
                      self._consecutive_anomalies, score,
                      features[0], int(features[5]),
                      int(features[6]), int(features[7]))
        else:
            # Reset streak — this window looks normal or borderline
            if self._consecutive_anomalies > 0:
                log.debug("[CLEARED] streak reset after %d window(s).",
                          self._consecutive_anomalies)
            self._consecutive_anomalies = 0
            # Only add confirmed-normal windows to the history pool
            self._normal_history.append(features)
            self._maybe_retrain()
            return  # not anomalous — done

        # ── Gate 2: must have CONFIRM_WINDOWS consecutive anomalous windows ──
        if self._consecutive_anomalies < CONFIRM_WINDOWS:
            return   # anomalous but not yet confirmed

        # ── Gate 3: cooldown — don't repeat-alert within ALERT_COOLDOWN_SECS ─
        now = time.monotonic()
        if (now - self._last_alert_time) < ALERT_COOLDOWN_SECS:
            log.debug("[SUPPRESSED] cooldown active (%.0fs remaining).",
                      ALERT_COOLDOWN_SECS - (now - self._last_alert_time))
            return

        # ── All three gates passed → fire alert ──────────────────────────────
        self._last_alert_time = now
        self._total_alerts   += 1
        self._consecutive_anomalies = 0   # reset after firing

        rate  = features[0]
        tcp   = int(features[1])
        udp   = int(features[2])
        icmp  = int(features[3])
        syn   = int(features[5])
        ips   = int(features[6])
        ports = int(features[7])

        # Classify the anomaly type for a more descriptive alert message
        if syn > 50:
            kind = "SYN flood / port scan"
        elif icmp > 100:
            kind = "ICMP flood"
        elif rate > 500:
            kind = "traffic volume spike"
        elif ips > 30:
            kind = "distributed scan / botnet"
        elif ports > 50:
            kind = "port sweep"
        else:
            kind = "statistical anomaly"

        msg = (
            f"{kind} | score={score:.3f} "
            f"rate={rate:.0f}pkt/s tcp={tcp} udp={udp} icmp={icmp} "
            f"syn={syn} src_ips={ips} dst_ports={ports}"
        )
        _write_alert(msg)

    # ── Main loop ────────────────────────────────────────────────────────────

    def run(self):
        log.info("IDS starting — training phase (%d s, %d-s windows).",
                 TRAIN_SECONDS, WINDOW_SECONDS)
        _write_alert("IDS started — entering training phase.")
        self._sniffer.start()

        try:
            while self._running:
                time.sleep(WINDOW_SECONDS)
                if not self._running:
                    break

                packets  = self._buf.drain()
                features = extract_features(packets, WINDOW_SECONDS)
                self._total_windows += 1

                # ── TRAINING ─────────────────────────────────────────────────
                if self._phase == "training":
                    self._training_vectors.append(features)
                    elapsed = time.monotonic() - self._phase_start

                    if (elapsed >= TRAIN_SECONDS
                            and len(self._training_vectors) >= MIN_TRAIN_SAMPLES):
                        self._enter_detection()
                    else:
                        log.debug(
                            "[TRAIN %3ds/%ds] pkts=%d  rate=%.1f/s  "
                            "tcp=%d  udp=%d  icmp=%d",
                            int(elapsed), TRAIN_SECONDS, len(packets),
                            features[0], int(features[1]),
                            int(features[2]), int(features[3]),
                        )

                # ── DETECTION ────────────────────────────────────────────────
                else:
                    self._evaluate(features, packets)

        finally:
            self._sniffer.stop()
            log.info("IDS stopped. windows=%d  alerts=%d",
                     self._total_windows, self._total_alerts)
            _write_alert(
                f"IDS stopped. windows={self._total_windows} "
                f"alerts={self._total_alerts}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    IDS().run()