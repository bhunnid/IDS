"""Live and replay anomaly detection for the lightweight IDS."""

from __future__ import annotations

import argparse
import ast
import threading
import time
from datetime import datetime
from pathlib import Path

import joblib
import pandas as pd
import psutil

from capture import start_capture
from features import FEATURE_COLS, WINDOW_SECONDS, live_windows

DEFAULT_MODEL_PATH = "ids_model.pkl"
DEFAULT_SCALER_PATH = "scaler.pkl"
DEFAULT_THRESHOLD = -0.10
DEFAULT_LOG_PATH = "alerts.log"


def load_artifacts(model_path: str = DEFAULT_MODEL_PATH, scaler_path: str = DEFAULT_SCALER_PATH):
    """Load the trained model and scaler from disk."""
    model_file = Path(model_path)
    scaler_file = Path(scaler_path)
    if not model_file.exists():
        raise FileNotFoundError(f"Model file not found: {model_file}")
    if not scaler_file.exists():
        raise FileNotFoundError(f"Scaler file not found: {scaler_file}")

    return joblib.load(model_file), joblib.load(scaler_file)


def predict(model, scaler, feature_row: dict[str, object], threshold: float) -> tuple[str, float]:
    """Return the window label and raw anomaly score."""
    feature_values = pd.DataFrame(
        [{column: float(feature_row[column]) for column in FEATURE_COLS}],
        columns=FEATURE_COLS,
    )
    scaled_values = scaler.transform(feature_values)
    score = float(model.decision_function(scaled_values)[0])
    label = "ALERT" if score < threshold else "NORMAL"
    return label, score


def _format_top_sources(top_src_ips: list[tuple[str, int]] | object) -> str:
    if not top_src_ips:
        return "[]"
    if isinstance(top_src_ips, str):
        try:
            parsed = ast.literal_eval(top_src_ips)
            top_src_ips = parsed if isinstance(parsed, list) else []
        except (ValueError, SyntaxError):
            top_src_ips = []
    parts = [f"{ip}({count})" for ip, count in list(top_src_ips)]
    return "[" + ", ".join(parts) + "]"


def log_alert(
    feature_row: dict[str, object],
    score: float,
    log_path: str = DEFAULT_LOG_PATH,
) -> None:
    """Append an anomaly event to the alerts log."""
    timestamp = datetime.fromtimestamp(float(feature_row["window_start"])).strftime("%Y-%m-%d %H:%M:%S")
    line = (
        f"{timestamp} | ANOMALY | score={score:+.4f} | "
        f"pkts={int(feature_row['packet_count'])} | "
        f"bytes={int(feature_row['byte_count'])} | "
        f"top_src_ips={_format_top_sources(feature_row.get('top_src_ips', []))}\n"
    )
    with Path(log_path).open("a", encoding="utf-8") as handle:
        handle.write(line)


def print_window(feature_row: dict[str, object], score: float, label: str) -> None:
    """Print one detection result line."""
    timestamp = datetime.fromtimestamp(float(feature_row["window_start"])).strftime("%H:%M:%S")
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent
    packet_count = int(feature_row["packet_count"])
    byte_count = int(feature_row["byte_count"])

    if label == "ALERT":
        print(
            f"[{timestamp}] ALERT  score={score:+.2f} "
            f"pkts={packet_count} bytes={byte_count} "
            f"cpu={cpu:.0f}% mem={mem:.0f}% "
            f"top_src={_format_top_sources(feature_row.get('top_src_ips', []))}"
        )
        return

    print(
        f"[{timestamp}] NORMAL score={score:+.2f} "
        f"pkts={packet_count} bytes={byte_count} cpu={cpu:.0f}% mem={mem:.0f}%"
    )


def run_live(
    model,
    scaler,
    threshold: float = DEFAULT_THRESHOLD,
    iface: str | None = None,
    window_size: int = WINDOW_SECONDS,
    log_path: str = DEFAULT_LOG_PATH,
    local_ips: list[str] | None = None,
) -> None:
    """Start live capture in a background thread and classify windows forever."""
    capture_thread = threading.Thread(
        target=start_capture,
        kwargs={"iface": iface, "save_path": None, "verbose": False},
        name="packet-capture",
        daemon=True,
    )
    capture_thread.start()

    print(
        f"[detect] Live detection started on {iface or 'default interface'} "
        f"with {window_size}s windows and threshold {threshold:+.2f}"
    )
    psutil.cpu_percent(interval=None)

    for feature_row in live_windows(window_size=window_size, local_ips=local_ips):
        label, score = predict(model, scaler, feature_row, threshold)
        print_window(feature_row, score, label)
        if label == "ALERT":
            log_alert(feature_row, score, log_path=log_path)


def run_replay(
    model,
    scaler,
    features_csv: str,
    threshold: float = DEFAULT_THRESHOLD,
    log_path: str = DEFAULT_LOG_PATH,
) -> None:
    """Replay pre-computed feature windows from CSV."""
    frame = pd.read_csv(features_csv)
    missing = [column for column in FEATURE_COLS if column not in frame.columns]
    if missing:
        raise ValueError(f"Replay CSV missing required columns: {missing}")

    if "window_start" not in frame.columns:
        frame["window_start"] = time.time()
    if "top_src_ips" not in frame.columns:
        frame["top_src_ips"] = "[]"

    print(f"[detect] Replaying {len(frame)} windows from {features_csv}")
    psutil.cpu_percent(interval=None)

    for row in frame.to_dict("records"):
        label, score = predict(model, scaler, row, threshold)
        print_window(row, score, label)
        if label == "ALERT":
            log_alert(row, score, log_path=log_path)
        time.sleep(0.05)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run live or replay IDS detection")
    parser.add_argument("--model", default=DEFAULT_MODEL_PATH, help="Path to ids_model.pkl")
    parser.add_argument("--scaler", default=DEFAULT_SCALER_PATH, help="Path to scaler.pkl")
    parser.add_argument("--iface", help="Capture interface name for live mode")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD, help="Anomaly score threshold")
    parser.add_argument("--window", type=int, default=WINDOW_SECONDS, help="Live window size in seconds")
    parser.add_argument("--replay", help="Optional features CSV for replay mode")
    parser.add_argument("--log", default=DEFAULT_LOG_PATH, help="Alert log file path")
    parser.add_argument(
        "--local-ip",
        action="append",
        default=[],
        help="Local IP to use for inbound/outbound live features; repeat for multiple IPs",
    )
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    model, scaler = load_artifacts(args.model, args.scaler)

    try:
        if args.replay:
            run_replay(model, scaler, args.replay, threshold=args.threshold, log_path=args.log)
        else:
            run_live(
                model,
                scaler,
                threshold=args.threshold,
                iface=args.iface,
                window_size=args.window,
                log_path=args.log,
                local_ips=args.local_ip,
            )
    except KeyboardInterrupt:
        print("\n[detect] Detection stopped.")
