"""
detect.py — Real-time anomaly detection.

Responsibilities:
  - Load trained Isolation Forest + StandardScaler from disk
  - Run live detection: start capture thread → read feature windows → classify
  - Print colour-coded results per window with score, packet stats, resources
  - Log every anomaly to alerts.log with timestamp, score, top source IPs
  - Provide offline replay mode for testing against pre-recorded feature CSVs

Architecture notes:
  - NO imports from capture.py — avoids circular dependency entirely
  - NO monkey-patching — capture.py's callback is self-contained
  - IP tracking comes from features.py's live_windows() generator,
    which returns "top_src_ips" in every feature dict (no shared mutable state)
  - Thread model:
      Thread-1 (daemon): start_capture() → puts packets on PACKET_QUEUE
      Thread-2 (main):   live_windows() drains PACKET_QUEUE → ML → output

Anomaly threshold guide:
   0.0  → flag everything the model scores negative (broadest)
  -0.05 → light buffer, reduces borderline false positives
  -0.10 → recommended default
  -0.20 → strict, only clear outliers

Usage:
    python detect.py --model ids_model.pkl --scaler scaler.pkl
    python detect.py --replay features.csv --threshold -0.05
    python detect.py --iface "Wi-Fi" --threshold -0.15
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

# Import the capture starter (NOT packet_queue — that comes from pipeline)
from capture import start_capture
from features import FEATURE_COLS, WINDOW_SECONDS, live_windows

# ── Constants ─────────────────────────────────────────────────────────────────
LOG_FILE          = "alerts.log"
DEFAULT_THRESHOLD = -0.10

# ANSI escape codes (work in Windows Terminal / PowerShell 7+)
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"


# ── Artefact loading ──────────────────────────────────────────────────────────

def load_artifacts(model_path: str, scaler_path: str):
    """
    Load and return (model, scaler).
    Exits with a clear message if either file is missing.
    """
    result = {}
    for name, path in [("model", model_path), ("scaler", scaler_path)]:
        try:
            result[name] = joblib.load(path)
            print(f"[detect] {name:<7} loaded ← {path}")
        except FileNotFoundError:
            print(f"[detect] ERROR: '{path}' not found.")
            print("[detect] Run train.py first to generate model and scaler files.")
            sys.exit(1)
    return result["model"], result["scaler"]


# ── Inference ─────────────────────────────────────────────────────────────────

def predict(model, scaler, feat: dict, threshold: float) -> tuple[str, float]:
    """
    Scale the feature vector and run Isolation Forest inference.

    Returns:
        label : "NORMAL" or "ANOMALY"
        score : raw decision_function score (higher = more normal)

    The threshold is applied here so it can be tuned at runtime
    without retraining the model.
    """
    X        = np.array([[feat[c] for c in FEATURE_COLS]], dtype=float)
    X_scaled = scaler.transform(X)
    score    = float(model.decision_function(X_scaled)[0])
    label    = "ANOMALY" if score < threshold else "NORMAL"
    return label, round(score, 4)


# ── Resource measurement ──────────────────────────────────────────────────────

def get_resources() -> tuple[float, float]:
    """
    Return (cpu_percent, memory_percent) for the current moment.
    cpu_percent(interval=None) is non-blocking — it measures CPU usage
    since the last call, adding negligible overhead per window.
    """
    return psutil.cpu_percent(interval=None), psutil.virtual_memory().percent


# ── Alert logging ─────────────────────────────────────────────────────────────

def log_alert(timestamp: str, score: float, feat: dict) -> None:
    """
    Append one anomaly event to alerts.log.

    Format:
        YYYY-MM-DD HH:MM:SS | ANOMALY | score=X | pkts=X | bytes=X | top_src=[ip(n), ...]
    """
    top_ips = feat.get("top_src_ips", [])
    ip_str  = ", ".join(f"{ip}({n})" for ip, n in top_ips) if top_ips else "n/a"
    line = (
        f"{timestamp} | ANOMALY | score={score:+.4f} | "
        f"pkts={feat.get('packet_count', 0)} | "
        f"bytes={feat.get('total_bytes', 0)} | "
        f"top_src=[{ip_str}]\n"
    )
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(line)


# ── Console output ────────────────────────────────────────────────────────────

def print_window(feat: dict, label: str, score: float,
                 cpu: float, mem: float) -> None:
    """Print one detection window result to stdout."""
    ts      = datetime.fromtimestamp(
                  feat.get("window_start", time.time())
              ).strftime("%H:%M:%S")
    pkts    = feat.get("packet_count", 0)
    total_b = feat.get("total_bytes",  0)
    top_ips = feat.get("top_src_ips",  [])

    if label == "ANOMALY":
        status   = f"{RED}⚠  ALERT: ANOMALY DETECTED{RESET}"
        ip_parts = [f"{YELLOW}{ip}{RESET}({n})" for ip, n in top_ips]
        ip_str   = f"  top_src=[{', '.join(ip_parts)}]" if ip_parts else ""
    else:
        status = f"{GREEN}✓  NORMAL{RESET}"
        ip_str = ""

    print(
        f"[{ts}] {status}  "
        f"score={score:+.4f}  pkts={pkts}  bytes={total_b}  "
        f"{CYAN}cpu={cpu:.1f}%  mem={mem:.1f}%{RESET}"
        f"{ip_str}"
    )


# ── Live detection ────────────────────────────────────────────────────────────

def run_live(model, scaler, threshold: float, iface: str | None = None) -> None:
    """
    Start packet capture in a background daemon thread, then run the
    detection loop in the foreground (main thread).

    Thread model:
        daemon thread → start_capture() → PACKET_QUEUE
        main thread   → live_windows() drains PACKET_QUEUE → predict → output
    """
    # Start capture as daemon so it auto-stops when the main thread exits
    capture_thread = threading.Thread(
        target=start_capture,
        kwargs={"iface": iface},
        daemon=True,
        name="CaptureThread",
    )
    capture_thread.start()

    print(
        f"[detect] Capture thread started\n"
        f"[detect] Window = {WINDOW_SECONDS}s | Threshold = {threshold} | "
        f"Log → {LOG_FILE}\n"
    )

    # Prime psutil so the first cpu_percent() returns a real value not 0.0
    psutil.cpu_percent(interval=None)

    # live_windows() is a generator in features.py — no monkey-patching needed
    for feat in live_windows():
        label, score = predict(model, scaler, feat, threshold)
        cpu, mem     = get_resources()

        print_window(feat, label, score, cpu, mem)

        if label == "ANOMALY":
            ts = datetime.fromtimestamp(
                     feat.get("window_start", time.time())
                 ).strftime("%Y-%m-%d %H:%M:%S")
            log_alert(ts, score, feat)


# ── Offline replay ────────────────────────────────────────────────────────────

def run_replay(model, scaler, features_csv: str, threshold: float) -> None:
    """
    Replay a pre-computed features CSV through the detector.

    Useful for:
      - Testing against Kali attack captures without re-running live capture
      - Comparing contamination values and thresholds reproducibly
    """
    df = pd.read_csv(features_csv)

    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        print(f"[detect] ERROR: features CSV missing columns: {missing}")
        sys.exit(1)

    print(f"[detect] Replaying {len(df)} windows from {features_csv}")
    print(f"[detect] Threshold = {threshold} | Log → {LOG_FILE}\n")

    psutil.cpu_percent(interval=None)

    for _, row in df.iterrows():
        feat  = row.to_dict()
        # top_src_ips is not in a CSV — provide empty list so print_window works
        feat.setdefault("top_src_ips", [])

        label, score = predict(model, scaler, feat, threshold)
        cpu, mem     = get_resources()

        print_window(feat, label, score, cpu, mem)

        if label == "ANOMALY":
            ts = datetime.fromtimestamp(
                     feat.get("window_start", time.time())
                 ).strftime("%Y-%m-%d %H:%M:%S")
            log_alert(ts, score, feat)

        time.sleep(0.05)   # brief pause so output is readable in terminal


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDS real-time anomaly detector")
    parser.add_argument("--model",     default="ids_model.pkl", metavar="PKL",
                        help="Trained model path")
    parser.add_argument("--scaler",    default="scaler.pkl",    metavar="PKL",
                        help="Trained scaler path")
    parser.add_argument("--iface",     default=None,            metavar="NAME",
                        help="Network interface for live capture")
    parser.add_argument("--replay",    default=None,            metavar="CSV",
                        help="Replay a features CSV (offline mode)")
    parser.add_argument("--threshold", default=DEFAULT_THRESHOLD, type=float,
                        metavar="FLOAT",
                        help=f"Anomaly score threshold (default: {DEFAULT_THRESHOLD})")
    args = parser.parse_args()

    model, scaler = load_artifacts(args.model, args.scaler)

    if args.replay:
        run_replay(model, scaler, args.replay, args.threshold)
    else:
        print("[detect] Live mode — press Ctrl+C to stop.\n")
        try:
            run_live(model, scaler, args.threshold, iface=args.iface)
        except KeyboardInterrupt:
            print("\n[detect] Stopped cleanly.")
