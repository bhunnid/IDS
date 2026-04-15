# ==========================
# HYBRID IDS (IMPROVED LOCAL)
# ==========================

import time
import threading
import collections
import numpy as np
from datetime import datetime

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from scapy.all import sniff, IP, TCP, UDP, ICMP

# -----------------------
# CONFIG
# -----------------------
WINDOW_SECONDS = 3
TRAIN_SECONDS = 180

IF_ESTIMATORS = 200
IF_CONTAMINATION = 0.01

SYN_FLOOD_THRESHOLD = 80          # tune for your network
PORT_SCAN_THRESHOLD = 25
TRAFFIC_SPIKE_FACTOR = 4          # compared to baseline mean

MIN_TRAIN_SAMPLES = 60

# -----------------------
# ALERT
# -----------------------
def alert(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] ALERT: {msg}"
    print(line)
    with open("alerts.log", "a") as f:
        f.write(line + "\n")


# -----------------------
# BUFFER
# -----------------------
class PacketBuffer:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = []

    def add(self, pkt):
        with self.lock:
            self.data.append(pkt)

    def drain(self):
        with self.lock:
            d = self.data
            self.data = []
        return d


# -----------------------
# FEATURE ENGINE
# -----------------------
def extract_features(pkts, window):
    if not pkts:
        return np.zeros(6), {}

    tcp = udp = icmp = syn = 0
    sizes = []

    src_ips = set()
    dst_ports = set()

    for p in pkts:
        if IP not in p:
            continue

        sizes.append(p[IP].len)
        src_ips.add(p[IP].src)

        if TCP in p:
            tcp += 1
            dst_ports.add(p[TCP].dport)
            if p[TCP].flags & 0x02:
                syn += 1

        elif UDP in p:
            udp += 1
            dst_ports.add(p[UDP].dport)

        elif ICMP in p:
            icmp += 1

    feat = np.array([
        len(pkts) / window,
        tcp + udp + icmp,
        float(np.mean(sizes)) if sizes else 0,
        len(src_ips),
        len(dst_ports),
        syn
    ], dtype=float)

    meta = {
        "syn": syn,
        "unique_ports": len(dst_ports),
        "rate": len(pkts) / window,
        "src_ips": len(src_ips)
    }

    return feat, meta


# -----------------------
# MODEL
# -----------------------
class Detector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.lock = threading.Lock()
        self.baseline_rate = []

    def train(self, X):
        X = np.array(X)
        Xs = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=IF_ESTIMATORS,
            contamination=IF_CONTAMINATION,
            random_state=42,
            n_jobs=-1
        )

        self.model.fit(Xs)

        # baseline stats for spike detection
        self.baseline_rate = X[:, 0]

        print(f"[INFO] Model trained on {len(X)} samples")

    def score(self, x):
        with self.lock:
            if self.model is None:
                return False, 0.0

            xs = self.scaler.transform(x.reshape(1, -1))
            pred = self.model.predict(xs)[0]
            score = self.model.decision_function(xs)[0]

        return pred == -1, float(score)

    def is_spike(self, rate):
        if len(self.baseline_rate) == 0:
            return False
        return rate > np.mean(self.baseline_rate) * TRAFFIC_SPIKE_FACTOR


# -----------------------
# IDS CORE
# -----------------------
class IDS:
    def __init__(self):
        self.buf = PacketBuffer()
        self.detector = Detector()

        self.training = []
        self.phase = "training"

        self.history_rates = collections.deque(maxlen=50)

        self.sniffer = threading.Thread(target=self._sniff, daemon=True)

    def _sniff(self):
        sniff(prn=self.buf.add, store=False)

    def start(self):
        self.sniffer.start()
        start = time.time()

        while True:
            time.sleep(WINDOW_SECONDS)

            pkts = self.buf.drain()
            feat, meta = extract_features(pkts, WINDOW_SECONDS)

            if self.phase == "training":
                self.training.append(feat)

                if time.time() - start > TRAIN_SECONDS and len(self.training) > MIN_TRAIN_SAMPLES:
                    self.detector.train(self.training)
                    self.phase = "detecting"
                    alert("Baseline complete — IDS now active")

            else:
                anomaly, score = self.detector.score(feat)

                self.history_rates.append(meta["rate"])

                # -----------------------------
                # RULE-BASED ATTACK DETECTION
                # -----------------------------

                syn_flood = meta["syn"] > SYN_FLOOD_THRESHOLD
                port_scan = meta["unique_ports"] > PORT_SCAN_THRESHOLD
                spike = self.detector.is_spike(meta["rate"])

                # -----------------------------
                # FINAL DECISION LOGIC
                # -----------------------------
                if anomaly or syn_flood or port_scan or spike:

                    reasons = []
                    if anomaly:
                        reasons.append(f"ML score={score:.3f}")
                    if syn_flood:
                        reasons.append("SYN flood suspected")
                    if port_scan:
                        reasons.append("Port scan suspected")
                    if spike:
                        reasons.append("Traffic spike detected")

                    alert(f"POSSIBLE ATTACK → {' | '.join(reasons)} | rate={meta['rate']:.1f} pkt/s")



# -----------------------
# RUN
# -----------------------
if __name__ == "__main__":
    IDS().start()