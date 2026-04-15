"""
ids_main.py — Lightweight Anomaly-Based Intrusion Detection System
===================================================================

HOW IT WORKS
------------
1. CAPTURE: Scapy sniffs all packets on the default network interface in a
   background thread, storing them in a thread-safe rolling buffer.

2. FEATURE EXTRACTION: Every WINDOW_SECONDS (2 s), the main loop drains the
   buffer and computes a lightweight feature vector for that window:
       [packet_rate, tcp_count, udp_count, icmp_count, avg_pkt_size,
        syn_count, unique_src_ips, unique_dst_ports]

3. TRAINING PHASE (first TRAIN_SECONDS, default 90 s): Feature vectors are
   collected but no alerts are raised. This baseline captures the machine's
   normal traffic pattern without any labelled data (fully unsupervised).

4. DETECTION PHASE: An Isolation Forest model is trained once on the baseline
   vectors. From then on, every new feature vector is scored. Isolation Forest
   marks a sample as anomalous when it is easily isolated from the rest (short
   average path length in random trees). Anomalous windows trigger an alert
   that is appended to alerts.log.

5. ADAPTIVE RE-TRAINING: The model is periodically re-trained on a rolling
   window of recent *normal* windows so it adapts to legitimate traffic shifts
   (e.g. a backup job that runs every hour) without requiring a restart.

RESOURCE USAGE
--------------
- One background sniffer thread (Scapy) — woken only on packet arrival.
- One main loop sleeping WINDOW_SECONDS between iterations.
- Isolation Forest with 100 estimators on ≤1800 samples — negligible RAM/CPU.

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
# CONFIGURATION  (tweak here — no external config file needed)
# ─────────────────────────────────────────────────────────────────────────────
WINDOW_SECONDS        = 2        # feature extraction interval (seconds)
TRAIN_SECONDS         = 90       # how long to collect baseline before training
ALERT_LOG             = "alerts.log"
INFO_LOG              = "ids.log"
IF_ESTIMATORS         = 100      # Isolation Forest n_estimators
IF_CONTAMINATION      = 0.03     # expected anomaly fraction (3 %)
RETRAIN_EVERY_WINDOWS = 150      # re-train model every N normal windows (~5 min)
NORMAL_HISTORY_SIZE   = 1800     # max normal windows kept for re-training
MIN_TRAIN_SAMPLES     = 20       # don't train until we have this many windows
INTERFACE             = None     # None → Scapy chooses the default interface
                                  # set e.g. "eth0" / "en0" to pin an interface

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging():
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s",
                             datefmt="%Y-%m-%d %H:%M:%S")
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Rotating file handler for operational info
    fh = RotatingFileHandler(INFO_LOG, maxBytes=5_000_000, backupCount=2)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    root.addHandler(fh)

    # Console: INFO and above only
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    root.addHandler(ch)

_setup_logging()
log = logging.getLogger(__name__)


def _write_alert(msg: str):
    """Append a timestamped alert line to alerts.log AND the info log."""
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
    """Collects packets captured by Scapy's sniffer thread."""

    def __init__(self):
        self._lock   = threading.Lock()
        self._buffer = []

    def add(self, pkt):
        with self._lock:
            self._buffer.append(pkt)

    def drain(self) -> list:
        """Return all buffered packets and reset the buffer."""
        with self._lock:
            pkts, self._buffer = self._buffer, []
        return pkts


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "packet_rate",       # packets per second
    "tcp_count",         # raw TCP packet count in window
    "udp_count",
    "icmp_count",
    "avg_pkt_size",      # mean IP total-length in bytes
    "syn_count",         # TCP SYN packets (connection initiations)
    "unique_src_ips",    # cardinality of source IP set
    "unique_dst_ports",  # cardinality of destination port set
]


def extract_features(packets: list, window_secs: float) -> np.ndarray:
    """
    Compute a 1-D feature vector from a list of Scapy packets captured
    during a window of `window_secs` seconds.
    Returns a numpy array of shape (len(FEATURE_NAMES),).
    """
    n = len(packets)
    if n == 0:
        return np.zeros(len(FEATURE_NAMES), dtype=float)

    tcp = udp = icmp = syn = 0
    pkt_sizes   = []
    src_ips     = set()
    dst_ports   = set()

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
            if tcp_layer.flags & 0x02:   # SYN flag
                syn += 1
        elif UDP in pkt:
            udp += 1
            dst_ports.add(pkt[UDP].dport)
        elif ICMP in pkt:
            icmp += 1

    avg_size = float(np.mean(pkt_sizes)) if pkt_sizes else 0.0

    return np.array([
        n / window_secs,          # packet_rate
        float(tcp),               # tcp_count
        float(udp),               # udp_count
        float(icmp),              # icmp_count
        avg_size,                 # avg_pkt_size
        float(syn),               # syn_count
        float(len(src_ips)),      # unique_src_ips
        float(len(dst_ports)),    # unique_dst_ports
    ], dtype=float)


# ─────────────────────────────────────────────────────────────────────────────
# ANOMALY DETECTOR  (wraps Isolation Forest)
# ─────────────────────────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Wraps scikit-learn IsolationForest.
    Predict returns True when the sample is anomalous.
    """

    def __init__(self):
        self._model: IsolationForest | None = None
        self._lock  = threading.Lock()

    def train(self, X: np.ndarray):
        """Fit a new model on the normal-traffic feature matrix X."""
        model = IsolationForest(
            n_estimators=IF_ESTIMATORS,
            contamination=IF_CONTAMINATION,
            random_state=42,
            n_jobs=1,         # keep it single-threaded to limit CPU
        )
        model.fit(X)
        with self._lock:
            self._model = model
        log.info("Model trained on %d windows.", len(X))

    def is_anomaly(self, features: np.ndarray) -> tuple[bool, float]:
        """
        Score one feature vector.
        Returns (is_anomaly: bool, score: float).
        score < 0 → anomaly, closer to -1 → more anomalous.
        """
        with self._lock:
            if self._model is None:
                return False, 0.0
            pred  = self._model.predict(features.reshape(1, -1))[0]   # 1 or -1
            score = self._model.decision_function(features.reshape(1, -1))[0]
        return (pred == -1), float(score)


# ─────────────────────────────────────────────────────────────────────────────
# SNIFFER THREAD
# ─────────────────────────────────────────────────────────────────────────────

class Sniffer(threading.Thread):
    """
    Runs Scapy's sniff() in a daemon thread.
    Packets are pushed into the shared PacketBuffer via a callback.
    """

    def __init__(self, buffer: PacketBuffer, iface=None):
        super().__init__(daemon=True, name="sniffer")
        self._buf   = buffer
        self._iface = iface
        self._stop  = threading.Event()

        # Suppress Scapy's verbose output
        scapy_conf.verb = 0

    def _pkt_callback(self, pkt):
        if not self._stop.is_set():
            self._buf.add(pkt)

    def run(self):
        log.info("Sniffer started on interface: %s",
                 self._iface or "default")
        try:
            sniff(
                iface     = self._iface,
                prn       = self._pkt_callback,
                store     = False,          # don't accumulate in Scapy's own buffer
                stop_filter = lambda _: self._stop.is_set(),
            )
        except PermissionError:
            log.critical("Packet capture requires root/admin privileges. "
                         "Re-run with sudo or as Administrator.")
            sys.exit(1)
        except Exception as exc:
            log.critical("Sniffer error: %s", exc, exc_info=True)
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

        self._phase             = "training"   # "training" | "detecting"
        self._phase_start       = time.monotonic()
        self._windows_since_rt  = 0            # windows since last re-train
        self._total_windows     = 0
        self._total_alerts      = 0

        # Graceful shutdown
        self._running = True
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT,  self._handle_signal)

    def _handle_signal(self, sig, _frame):
        log.info("Shutdown signal received (%s).", signal.Signals(sig).name)
        self._running = False

    # ── Phase helpers ────────────────────────────────────────────────────────

    def _enter_detection(self):
        X = np.array(self._training_vectors)
        self._detector.train(X)
        # Seed normal history with training data
        for v in self._training_vectors:
            self._normal_history.append(v)
        self._phase = "detecting"
        log.info("Switched to DETECTION mode after %d training windows.",
                 len(self._training_vectors))
        _write_alert("IDS entered DETECTION mode — baseline training complete.")

    def _maybe_retrain(self):
        self._windows_since_rt += 1
        if (self._windows_since_rt >= RETRAIN_EVERY_WINDOWS
                and len(self._normal_history) >= MIN_TRAIN_SAMPLES):
            X = np.array(self._normal_history)
            self._detector.train(X)
            self._windows_since_rt = 0
            log.info("Adaptive re-train complete (%d normal windows in history).",
                     len(self._normal_history))

    # ── Main loop ────────────────────────────────────────────────────────────

    def run(self):
        log.info("IDS starting — training phase (%d s).", TRAIN_SECONDS)
        _write_alert("IDS started — entering training phase.")
        self._sniffer.start()

        try:
            while self._running:
                time.sleep(WINDOW_SECONDS)
                if not self._running:
                    break

                packets = self._buf.drain()
                features = extract_features(packets, WINDOW_SECONDS)
                self._total_windows += 1

                # ── TRAINING PHASE ───────────────────────────────────────────
                if self._phase == "training":
                    self._training_vectors.append(features)
                    elapsed = time.monotonic() - self._phase_start

                    if (elapsed >= TRAIN_SECONDS
                            and len(self._training_vectors) >= MIN_TRAIN_SAMPLES):
                        self._enter_detection()
                    else:
                        log.debug(
                            "[TRAIN %3ds] pkts=%d  rate=%.1f/s  tcp=%d  udp=%d",
                            int(elapsed), len(packets),
                            features[0], features[1], features[2],
                        )

                # ── DETECTION PHASE ──────────────────────────────────────────
                else:
                    anomaly, score = self._detector.is_anomaly(features)

                    if anomaly:
                        self._total_alerts += 1
                        rate   = features[0]
                        tcp    = int(features[1])
                        udp    = int(features[2])
                        icmp   = int(features[3])
                        syn    = int(features[5])
                        ips    = int(features[6])
                        ports  = int(features[7])
                        msg = (
                            f"Anomaly detected (score={score:.3f}) | "
                            f"rate={rate:.1f}pkt/s tcp={tcp} udp={udp} "
                            f"icmp={icmp} syn={syn} src_ips={ips} "
                            f"dst_ports={ports}"
                        )
                        _write_alert(msg)
                    else:
                        # Accumulate normal windows for adaptive re-training
                        self._normal_history.append(features)
                        self._maybe_retrain()
                        log.debug(
                            "[DETECT] score=%.3f  pkts=%d  rate=%.1f/s  "
                            "syn=%d  src_ips=%d",
                            score, len(packets), features[0],
                            int(features[5]), int(features[6]),
                        )

        finally:
            self._sniffer.stop()
            log.info(
                "IDS stopped. Windows processed: %d | Alerts raised: %d",
                self._total_windows, self._total_alerts,
            )
            _write_alert(
                f"IDS stopped. Windows={self._total_windows} "
                f"Alerts={self._total_alerts}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    IDS().run()
