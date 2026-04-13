"""Feature extraction for offline training and live detection."""

from __future__ import annotations

import argparse
import queue
import time
from collections import Counter
from typing import Iterable

import pandas as pd

from pipeline import PACKET_QUEUE

WINDOW_SECONDS = 10
FEATURE_COLS = [
    "packet_count",
    "byte_count",
    "avg_packet_size",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "unique_src_ips",
]


def packets_to_features(packets: list[dict[str, object]]) -> dict[str, object]:
    """Compute one feature record from a list of packet metadata dicts."""
    if not packets:
        return {
            "packet_count": 0,
            "byte_count": 0,
            "avg_packet_size": 0.0,
            "tcp_count": 0,
            "udp_count": 0,
            "icmp_count": 0,
            "unique_src_ips": 0,
            "top_src_ips": [],
        }

    protocol_counts = Counter(str(packet["protocol"]) for packet in packets)
    source_counts = Counter(str(packet["src_ip"]) for packet in packets)
    byte_count = sum(int(packet["size"]) for packet in packets)
    packet_count = len(packets)

    return {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "avg_packet_size": round(byte_count / packet_count, 2),
        "tcp_count": protocol_counts["TCP"],
        "udp_count": protocol_counts["UDP"],
        "icmp_count": protocol_counts["ICMP"],
        "unique_src_ips": len(source_counts),
        "top_src_ips": source_counts.most_common(5),
    }


def _iter_window_records(
    packet_records: Iterable[dict[str, object]],
    window_size: int,
) -> Iterable[dict[str, object]]:
    packets = list(packet_records)
    if not packets:
        return []

    packets.sort(key=lambda row: float(row["timestamp"]))
    first_timestamp = float(packets[0]["timestamp"])
    last_timestamp = float(packets[-1]["timestamp"])
    total_windows = int((last_timestamp - first_timestamp) // window_size) + 1

    bucket_map: dict[int, list[dict[str, object]]] = {index: [] for index in range(total_windows)}
    for record in packets:
        window_id = int((float(record["timestamp"]) - first_timestamp) // window_size)
        bucket_map[window_id].append(record)

    rows: list[dict[str, object]] = []
    for window_id in range(total_windows):
        window_packets = bucket_map.get(window_id, [])
        feature_row = packets_to_features(window_packets)
        feature_row["window_id"] = window_id
        feature_row["window_start"] = round(first_timestamp + (window_id * window_size), 3)
        rows.append(feature_row)
    return rows


def windowed_features_from_csv(csv_path: str, window_size: int = WINDOW_SECONDS) -> pd.DataFrame:
    """Convert a raw packet CSV into one feature row per time window."""
    packet_df = pd.read_csv(csv_path)
    if packet_df.empty:
        raise ValueError(f"No packet data found in {csv_path}")

    required = {"timestamp", "src_ip", "dst_ip", "size", "protocol"}
    missing = sorted(required.difference(packet_df.columns))
    if missing:
        raise ValueError(f"Packet CSV missing required columns: {missing}")

    rows = list(_iter_window_records(packet_df.to_dict("records"), window_size))
    feature_df = pd.DataFrame(rows)
    if feature_df.empty:
        raise ValueError(f"No feature windows could be generated from {csv_path}")

    ordered_columns = ["window_id", "window_start", *FEATURE_COLS, "top_src_ips"]
    return feature_df[ordered_columns]


def live_windows(window_size: int = WINDOW_SECONDS):
    """Yield one feature dict for each completed live capture window."""
    current_window_start = time.time()
    current_window_end = current_window_start + window_size
    buffer: list[dict[str, object]] = []

    while True:
        timeout = max(0.0, current_window_end - time.time())

        if timeout == 0.0:
            feature_row = packets_to_features(buffer)
            feature_row["window_start"] = round(current_window_start, 3)
            yield feature_row
            buffer = []
            current_window_start = current_window_end
            current_window_end = current_window_start + window_size
            continue

        try:
            packet = PACKET_QUEUE.get(timeout=min(timeout, 0.5))
            packet_ts = float(packet.get("timestamp", time.time()))

            while packet_ts >= current_window_end:
                feature_row = packets_to_features(buffer)
                feature_row["window_start"] = round(current_window_start, 3)
                yield feature_row
                buffer = []
                current_window_start = current_window_end
                current_window_end = current_window_start + window_size

            buffer.append(packet)
        except queue.Empty:
            feature_row = packets_to_features(buffer)
            feature_row["window_start"] = round(current_window_start, 3)
            yield feature_row
            buffer = []
            current_window_start = current_window_end
            current_window_end = current_window_start + window_size


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract IDS feature windows from packet CSV")
    parser.add_argument("--input", required=True, help="Raw packet CSV captured by capture.py")
    parser.add_argument("--output", required=True, help="Output CSV path for feature windows")
    parser.add_argument(
        "--window",
        type=int,
        default=WINDOW_SECONDS,
        help=f"Window size in seconds (default: {WINDOW_SECONDS})",
    )
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    frame = windowed_features_from_csv(args.input, window_size=args.window)
    frame.to_csv(args.output, index=False)
    print(f"[features] Wrote {len(frame)} feature windows to {args.output}")
