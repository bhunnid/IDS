import time
import threading
import collections
import numpy as np
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ======================
# CONFIG (IMPROVED)
# ======================
WINDOW_SECONDS = 2

TRAIN_SECONDS = 120
MIN_TRAIN_SAMPLES = 80

IF_ESTIMATORS = 200
IF_CONTAMINATION = 0.005   # lower = fewer false alarms

SMOOTHING_ALPHA = 0.3

ANOMALY_HIT_THRESHOLD = 3   # consecutive anomalies = attack

HISTORY_SIZE = 300

# ======================
# LOGGING
# ======================
def write_alert(msg, level="ALERT"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {level}: {msg}"
    print(line)
    with open("alerts.log", "a") as f:
        f.write(line + "\n")


# ======================
# FEATURE ENGINE (STRONGER)
# ======================
def extract_features(pkts, window):
    if not pkts:
        return np.zeros(7)

    sizes = []
    tcp = udp = icmp = 0
    src_ips = set()
    dst_ports = set()

    syn_count = 0

    for p in pkts:
        if IP not in p:
            continue

        sizes.append(p[IP].len)
        src_ips.add(p[IP].src)

        if TCP in p:
            tcp += 1
            dst_ports.add(p[TCP].dport)

            # SYN flood signal
            if p[TCP].flags == "S":
                syn_count += 1

        elif UDP in p:
            udp += 1
            dst_ports.add(p[UDP].dport)

        elif ICMP in p:
            icmp += 1

    pkt_rate = len(pkts) / window
    unique_ips = len(src_ips)
    port_diversity = len(dst_ports)
    avg_size = np.mean(sizes) if sizes else 0

    return np.array([
        pkt_rate,
        tcp,
        udp,
        icmp,
        unique_ips,
        port_diversity,
        syn_count
    ], dtype=float)


# ======================
# MODEL
# ======================
class Detector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=IF_ESTIMATORS,
            contamination=IF_CONTAMINATION,
            random_state=42,
            n_jobs=-1
        )
        self.lock = threading.Lock()

    def train(self, X):
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs)
        write_alert(f"Model trained on {len(X)} samples", "INFO")

    def score(self, x):
        with self.lock:
            xs = self.scaler.transform(x.reshape(1, -1))

            score = self.model.decision_function(xs)[0]
            pred = self.model.predict(xs)[0]  # -1 anomaly

        return pred == -1, score


# ======================
# IDS CORE (IMPROVED)
# ======================
class IDS:
    def __init__(self):
        self.training = []
        self.phase = "training"

        self.detector = Detector()

        self.score_history = collections.deque(maxlen=HISTORY_SIZE)
        self.anomaly_streak = 0

        self.last_score = 0.0

    def sniff_loop(self):
        self.buffer = []

        def handler(pkt):
            self.buffer.append(pkt)

        sniff(prn=handler, store=False)

    def start(self):
        threading.Thread(target=self.sniff_loop, daemon=True).start()

        start = time.time()

        while True:
            time.sleep(WINDOW_SECONDS)

            pkts = self.buffer
            self.buffer = []

            feat = extract_features(pkts, WINDOW_SECONDS)

            # ======================
            # TRAINING PHASE
            # ======================
            if self.phase == "training":
                self.training.append(feat)

                if time.time() - start > TRAIN_SECONDS and len(self.training) > MIN_TRAIN_SAMPLES:
                    self.detector.train(np.array(self.training))
                    self.phase = "detecting"
                    write_alert("Switched to DETECTION mode", "INFO")

                continue

            # ======================
            # DETECTION PHASE
            # ======================
            anomaly, score = self.detector.score(feat)

            # EWMA smoothing
            self.last_score = (
                SMOOTHING_ALPHA * score +
                (1 - SMOOTHING_ALPHA) * self.last_score
            )

            self.score_history.append(self.last_score)

            mean = np.mean(self.score_history)
            std = np.std(self.score_history) + 1e-6

            z_score = (self.last_score - mean) / std

            # ======================
            # ATTACK LOGIC (IMPROVED)
            # ======================

            is_suspicious = (
                anomaly or
                z_score < -2.5 or
                len(feat) > 0 and feat[0] > 80  # traffic spike rule
            )

            if is_suspicious:
                self.anomaly_streak += 1
            else:
                self.anomaly_streak = 0

            # 🚨 FINAL ATTACK DECISION
            if self.anomaly_streak >= ANOMALY_HIT_THRESHOLD:
                write_alert(
                    f"POSSIBLE ATTACK DETECTED | score={self.last_score:.3f} | z={z_score:.2f} | feat={feat.tolist()}",
                    "CRITICAL"
                )
                self.anomaly_streak = 0


# ======================
# RUN
# ======================
if __name__ == "__main__":
    IDS().start()