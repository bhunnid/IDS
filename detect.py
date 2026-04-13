"""
detect.py — Real-time anomaly detection using the trained Isolation Forest model.

Improvements over v1:
    ✔ Loads StandardScaler (scaler.pkl) and normalises features before inference
    ✔ Writes all alerts to alerts.log for offline evaluation
    ✔ Logs CPU + memory usage per window (proves "lightweight" claim in report)
    ✔ Tracks and displays suspicious IPs within each anomalous window
    ✔ Tunable anomaly threshold (default -0.1 instead of hard 0.0)
    ✔ Fixed 10-second window cadence enforced in extract_features_from_queue

Anomaly threshold guide:
     0.0  → flag anything the model scores negative (broadest)
    -0.05 → small buffer, reduces borderline false positives
    -0.10 → recommended default — only flag clearly anomalous windows
    -0.20 → strict — only the most severe deviations trigger alerts

Usage:
    python detect.py --model ids_model.pkl
    python detect.py --model ids_model.pkl --replay features.csv
    python detect.py --model ids_model.pkl --threshold -0.15
"""

import argparse
import sys
import threading
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
import psutil

from capture import packet_queue, start_capture
from features import extract_features_from_queue, FEATURE_COLS, WINDOW_SECONDS

# ── Constants ────────────────────────────────────────────────────────────────
LOG_FILE          = "alerts.log"
DEFAULT_THRESHOLD = -0.10   # scores below this trigger ALERT (tune for your report)

# ANSI colours
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"


# ── Model + scaler loading ───────────────────────────────────────────────────

def load_artifacts(model_path: str, scaler_path: str):
    """Load trained Isolation Forest and its paired StandardScaler."""
    artifacts = {}
    for name, path in [("model", model_path), ("scaler", scaler_path)]:
        try:
            artifacts[name] = joblib.load(path)
            print(f"[detect] Loaded {name} from {path}")
        except FileNotFoundError:
            print(f"[detect] ERROR: '{path}' not found. Run train.py first.")
            sys.exit(1)
    return artifacts["model"], artifacts["scaler"]


# ── Inference ────────────────────────────────────────────────────────────────

def predict(model, scaler, feat: dict, threshold: float) -> tuple[str, float]:
    """
    Normalise the feature vector, run inference, apply tunable threshold.
    Returns (label, score).
      label = 'NORMAL' or 'ANOMALY'
      score = raw Isolation Forest decision score (higher = more normal)
    """
    X        = np.array([[feat[c] for c in FEATURE_COLS]])
    X_scaled = scaler.transform(X)                    # apply same scaling as training
    score    = model.decision_function(X_scaled)[0]
    label    = "ANOMALY" if score < threshold else "NORMAL"
    return label, round(float(score), 4)


# ── Suspicious IP tracking ───────────────────────────────────────────────────

# Rolling buffer: capture.py pushes full packet dicts here when available.
# We read from it in get_top_ips() to find the noisiest sources in a window.
_recent_packets: list = []

def register_packet_hook():
    """
    Monkey-patch capture.py's on_packet so we also record raw packet dicts
    into _recent_packets for IP tracking. Called once at startup.
    """
    import capture as cap
    original = cap.on_packet

    def hooked(pkt, writer=None):
        original(pkt, writer)
        record = cap.parse_packet(pkt)
        if record:
            _recent_packets.append(record)
            # Keep only the last 5000 packets to cap memory usage
            if len(_recent_packets) > 5000:
                _recent_packets.pop(0)

    cap.on_packet = hooked


def get_top_ips(n: int = 3) -> list[tuple[str, int]]:
    """Return the top-n source IPs by packet count from the recent buffer."""
    from collections import Counter
    counts = Counter(p["src_ip"] for p in _recent_packets)
    return counts.most_common(n)


# ── Logging ──────────────────────────────────────────────────────────────────

def log_alert(ts: str, score: float, feat: dict, top_ips: list):
    """Append anomaly event to alerts.log."""
    ip_str = ", ".join(f"{ip}({n}pkts)" for ip, n in top_ips) or "n/a"
    line   = (f"{ts} | ANOMALY | score={score:+.4f} | "
              f"pkts={feat.get('packet_count',0)} | "
              f"bytes={feat.get('total_bytes',0)} | "
              f"top_src_ips=[{ip_str}]\n")
    with open(LOG_FILE, "a") as f:
        f.write(line)


# ── Resource measurement ─────────────────────────────────────────────────────

def get_resource_usage() -> tuple[float, float]:
    """Return current process CPU % and system memory % (for report evidence)."""
    cpu = psutil.cpu_percent(interval=None)   # non-blocking — returns since last call
    mem = psutil.virtual_memory().percent
    return cpu, mem


# ── Console output ───────────────────────────────────────────────────────────

def print_result(feat: dict, label: str, score: float,
                 cpu: float, mem: float, top_ips: list):
    """Format and print one detection window to the console."""
    ts    = datetime.fromtimestamp(feat.get("window_start", time.time())).strftime("%H:%M:%S")
    pkts  = feat.get("packet_count", 0)
    bytes_= feat.get("total_bytes", 0)

    if label == "ANOMALY":
        status = f"{RED}⚠  ALERT: ANOMALY DETECTED{RESET}"
        ip_info = ""
        if top_ips:
            ips = ", ".join(f"{YELLOW}{ip}{RESET}({n})" for ip, n in top_ips)
            ip_info = f"  top_src=[{ips}]"
    else:
        status  = f"{GREEN}✓  NORMAL{RESET}"
        ip_info = ""

    resource = f"{CYAN}cpu={cpu:.1f}%  mem={mem:.1f}%{RESET}"
    print(f"[{ts}] {status}  score={score:+.4f}  pkts={pkts}  bytes={bytes_}"
          f"  {resource}{ip_info}")


# ── Live detection ───────────────────────────────────────────────────────────

def run_live(model, scaler, threshold: float, iface=None):
    """Start capture in a background thread; run detection in the foreground."""
    register_packet_hook()

    capture_thread = threading.Thread(
        target=start_capture,
        kwargs={"iface": iface},
        daemon=True,
    )
    capture_thread.start()
    print(f"[detect] Capture thread started | window={WINDOW_SECONDS}s | "
          f"threshold={threshold}\n")

    # Prime psutil so the first cpu_percent() call returns a real value
    psutil.cpu_percent(interval=None)

    for feat in extract_features_from_queue(packet_queue):
        label, score = predict(model, scaler, feat, threshold)
        cpu, mem     = get_resource_usage()
        top_ips      = get_top_ips() if label == "ANOMALY" else []

        print_result(feat, label, score, cpu, mem, top_ips)

        if label == "ANOMALY":
            ts = datetime.fromtimestamp(feat.get("window_start", time.time())
                                        ).strftime("%Y-%m-%d %H:%M:%S")
            log_alert(ts, score, feat, top_ips)
            # Clear the IP buffer after logging so stale data doesn't bleed
            # into the next window's suspicious-IP report
            _recent_packets.clear()


# ── Offline replay ───────────────────────────────────────────────────────────

def run_replay(model, scaler, features_csv: str, threshold: float):
    """Replay a features CSV offline — useful for testing with Kali attack logs."""
    df = pd.read_csv(features_csv)
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        print(f"[detect] ERROR: Missing columns: {missing}")
        sys.exit(1)

    print(f"[detect] Replaying {len(df)} windows | threshold={threshold}\n")
    psutil.cpu_percent(interval=None)

    for _, row in df.iterrows():
        feat         = row.to_dict()
        label, score = predict(model, scaler, feat, threshold)
        cpu, mem     = get_resource_usage()

        print_result(feat, label, score, cpu, mem, top_ips=[])

        if label == "ANOMALY":
            ts = datetime.fromtimestamp(feat.get("window_start", time.time())
                                        ).strftime("%Y-%m-%d %H:%M:%S")
            log_alert(ts, score, feat, [])

        time.sleep(0.05)   # slight delay so output is readable


# ── CLI entry point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDS real-time anomaly detector")
    parser.add_argument("--model",     default="ids_model.pkl", metavar="PKL",
                        help="Trained model path (default: ids_model.pkl)")
    parser.add_argument("--scaler",    default="scaler.pkl",    metavar="PKL",
                        help="Trained scaler path (default: scaler.pkl)")
    parser.add_argument("--iface",     metavar="IFACE",
                        help="Network interface for live capture (optional)")
    parser.add_argument("--replay",    metavar="CSV",
                        help="Replay a features CSV instead of live capture")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help=f"Anomaly score threshold (default: {DEFAULT_THRESHOLD}). "
                             "Scores below this trigger ALERT.")
    args = parser.parse_args()

    model, scaler = load_artifacts(args.model, args.scaler)
    print(f"[detect] Alert log → {LOG_FILE}\n")

    if args.replay:
        run_replay(model, scaler, args.replay, args.threshold)
    else:
        print("[detect] Starting live detection. Press Ctrl+C to stop.\n")
        try:
            run_live(model, scaler, args.threshold, iface=args.iface)
        except KeyboardInterrupt:
            print("\n[detect] Stopped.")
