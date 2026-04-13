"""
features.py — Convert raw packets into time-window feature vectors
Lightweight flow-based feature extraction for IDS.
"""

import time
import argparse
from collections import defaultdict

import pandas as pd

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

WINDOW_SECONDS = 10

FEATURE_COLS = [
    "packet_count",
    "avg_pkt_size",
    "total_bytes",
    "unique_ips",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "other_count"
]


# ─────────────────────────────────────────────
# Core feature extraction
# ─────────────────────────────────────────────

def packets_to_features(packets: list) -> dict:
    """
    Convert a list of packet dictionaries into a feature vector.

    Expected packet format:
        {
            "src_ip": str,
            "dst_ip": str,
            "size": int,
            "protocol": str
        }
    """

    if not packets:
        return {col: 0 for col in FEATURE_COLS}

    sizes = [p["size"] for p in packets]

    all_ips = set()
    proto_counts = defaultdict(int)

    for p in packets:
        all_ips.add(p["src_ip"])
        all_ips.add(p["dst_ip"])
        proto_counts[p["protocol"]] += 1

    return {
        "packet_count": len(packets),
        "avg_pkt_size": round(sum(sizes) / len(sizes), 2),
        "total_bytes": sum(sizes),
        "unique_ips": len(all_ips),
        "tcp_count": proto_counts["TCP"],
        "udp_count": proto_counts["UDP"],
        "icmp_count": proto_counts["ICMP"],
        "other_count": proto_counts["OTHER"],
    }


# ─────────────────────────────────────────────
# CSV-based feature extraction (offline training)
# ─────────────────────────────────────────────

def windowed_features_from_csv(csv_path: str, window_sec: int = WINDOW_SECONDS) -> pd.DataFrame:
    df = pd.read_csv(csv_path)

    if df.empty:
        raise ValueError("CSV file is empty")

    df["timestamp"] = df["timestamp"].astype(float)

    t_min = df["timestamp"].min()
    df["window"] = ((df["timestamp"] - t_min) // window_sec).astype(int)

    rows = []

    for window_id, group in df.groupby("window"):
        packets = group.to_dict("records")
        feat = packets_to_features(packets)

        feat["window_id"] = int(window_id)
        feat["window_start"] = round(t_min + window_id * window_sec, 2)

        rows.append(feat)

    feature_df = pd.DataFrame(rows)

    return feature_df[
        ["window_id", "window_start"] + FEATURE_COLS
    ]


# ─────────────────────────────────────────────
# Live feature extraction (REAL-TIME IDS)
# ─────────────────────────────────────────────

def extract_features_from_queue(packet_queue, window_sec: int = WINDOW_SECONDS):
    """
    Generator that produces feature vectors every fixed time window.

    Key property:
    - Time windows are wall-clock aligned (no drift)
    - Empty windows still produce zero vectors
    """

    buffer = []

    window_start = time.time()
    window_end = window_start + window_sec

    while True:

        while not packet_queue.empty():
            buffer.append(packet_queue.get_nowait())

        now = time.time()

        if now >= window_end:

            feat = packets_to_features(buffer)
            feat["window_start"] = round(window_start, 2)

            buffer = []

            window_start = window_end
            window_end = window_start + window_sec

            yield feat

        else:
            time.sleep(min(0.2, window_end - now))


# ─────────────────────────────────────────────
# CLI (offline feature extraction)
# ─────────────────────────────────────────────

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Extract IDS features from CSV")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--window", type=int, default=WINDOW_SECONDS)

    args = parser.parse_args()

    print(f"[features] Processing {args.input}")

    df = windowed_features_from_csv(args.input, args.window)

    df.to_csv(args.output, index=False)

    print(f"[features] Saved {len(df)} windows to {args.output}")
    print(df.head().to_string(index=False))