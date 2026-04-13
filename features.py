"""
features.py — Convert raw packets into time-window feature vectors
Groups packets into fixed time windows and computes aggregate features.

Features per window:
    packet_count     — total number of packets
    avg_pkt_size     — average packet size in bytes
    total_bytes      — sum of all packet sizes
    unique_ips       — number of distinct source + destination IPs seen
    tcp_count        — packets using TCP
    udp_count        — packets using UDP
    icmp_count       — packets using ICMP
    other_count      — packets with other/unknown protocol

Usage (from CSV file):
    python features.py --input data.csv --output features.csv

Usage (live, reading from capture.py's shared queue):
    Import extract_features_from_queue() in detect.py
"""

import argparse
import time
from collections import defaultdict

import pandas as pd

# Window size in seconds — tweak this to balance responsiveness vs. stability
WINDOW_SECONDS = 10


def packets_to_features(packets: list) -> dict:
    """
    Compute feature vector from a list of packet dicts.
    Each packet dict: {timestamp, src_ip, dst_ip, size, protocol}
    """
    if not packets:
        # Return a zeroed-out feature vector so the window isn't silently dropped
        return {
            "packet_count": 0,
            "avg_pkt_size": 0.0,
            "total_bytes":  0,
            "unique_ips":   0,
            "tcp_count":    0,
            "udp_count":    0,
            "icmp_count":   0,
            "other_count":  0,
        }

    sizes     = [p["size"] for p in packets]
    protocols = [p["protocol"] for p in packets]

    # Unique IPs = union of all sources and destinations seen in this window
    all_ips = set()
    for p in packets:
        all_ips.add(p["src_ip"])
        all_ips.add(p["dst_ip"])

    proto_counts = defaultdict(int)
    for proto in protocols:
        proto_counts[proto] += 1

    return {
        "packet_count": len(packets),
        "avg_pkt_size": round(sum(sizes) / len(sizes), 2),
        "total_bytes":  sum(sizes),
        "unique_ips":   len(all_ips),
        "tcp_count":    proto_counts["TCP"],
        "udp_count":    proto_counts["UDP"],
        "icmp_count":   proto_counts["ICMP"],
        "other_count":  proto_counts["OTHER"],
    }


def windowed_features_from_csv(csv_path: str, window_sec: int = WINDOW_SECONDS) -> pd.DataFrame:
    """
    Read a CSV produced by capture.py and return a DataFrame of feature vectors,
    one row per time window.
    """
    df = pd.read_csv(csv_path)
    if df.empty:
        raise ValueError(f"No data found in {csv_path}")

    df["timestamp"] = df["timestamp"].astype(float)

    # Assign each packet to a window bucket based on its timestamp
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
    # Reorder columns for readability
    cols = ["window_id", "window_start",
            "packet_count", "avg_pkt_size", "total_bytes",
            "unique_ips", "tcp_count", "udp_count", "icmp_count", "other_count"]
    return feature_df[cols]


def extract_features_from_queue(packet_queue, window_sec: int = WINDOW_SECONDS):
    """
    Generator that reads from capture.py's shared packet_queue and yields
    one feature-vector dict every `window_sec` seconds.

    Window consistency guarantee:
        Windows are anchored to the wall clock, not to when packets arrive.
        Each boundary advances by exactly window_sec so irregular bursts never
        stretch or shrink a window. An empty window still yields a zeroed
        feature vector — silence is itself a signal worth evaluating.
    """
    buffer = []

    # Anchor the first boundary to now; pre-compute the deadline
    window_start = time.time()
    window_end   = window_start + window_sec

    while True:
        # Drain everything currently in the queue (non-blocking)
        while not packet_queue.empty():
            buffer.append(packet_queue.get_nowait())

        now = time.time()
        if now >= window_end:
            feat = packets_to_features(buffer)
            feat["window_start"] = round(window_start, 2)
            buffer = []

            # Advance by exactly window_sec — avoids clock-skew accumulation
            window_start = window_end
            window_end   = window_start + window_sec

            yield feat
        else:
            # Sleep at most 200 ms, but never past the window deadline
            remaining = window_end - now
            time.sleep(min(0.2, remaining))


# ── CLI entry point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract flow features from captured packets")
    parser.add_argument("--input",  required=True,  metavar="CSV", help="Input CSV from capture.py")
    parser.add_argument("--output", required=True,  metavar="CSV", help="Output features CSV")
    parser.add_argument("--window", type=int, default=WINDOW_SECONDS,
                        help=f"Time window in seconds (default: {WINDOW_SECONDS})")
    args = parser.parse_args()

    print(f"[features] Reading {args.input} with {args.window}s windows...")
    features_df = windowed_features_from_csv(args.input, args.window)
    features_df.to_csv(args.output, index=False)
    print(f"[features] Saved {len(features_df)} feature windows to {args.output}")
    print(features_df.to_string(index=False))
