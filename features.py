"""Feature extraction for offline training and live detection."""

from __future__ import annotations

import argparse
import queue
import socket
import time
from collections import Counter, defaultdict
from statistics import mean
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
    "unique_dst_ips",
    "unique_host_pairs",
    "unique_service_ports",
    "new_connection_count",
    "avg_connection_duration",
    "max_connection_duration",
    "avg_inter_arrival_ms",
    "max_packets_per_src",
    "avg_packets_per_src",
    "avg_bytes_per_src",
    "inbound_packet_count",
    "outbound_packet_count",
    "inbound_byte_count",
    "outbound_byte_count",
]


def default_local_ips() -> set[str]:
    """Best-effort detection of local IP addresses for directional features."""
    local_ips = {"127.0.0.1"}
    hostnames = {socket.gethostname(), socket.getfqdn()}
    for host in hostnames:
        try:
            _, _, addresses = socket.gethostbyname_ex(host)
            local_ips.update(addresses)
        except socket.gaierror:
            continue
    return {ip for ip in local_ips if ip}


def _safe_int(value: object) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _normalize_local_ips(local_ips: Iterable[str] | None) -> set[str]:
    if local_ips is None:
        return set()
    if isinstance(local_ips, str):
        return {local_ips} if local_ips else set()
    return {str(ip) for ip in local_ips if str(ip)}


def packets_to_features(
    packets: list[dict[str, object]],
    local_ips: Iterable[str] | None = None,
) -> dict[str, object]:
    """Compute one feature record from a list of packet metadata dicts."""
    tracked_local_ips = _normalize_local_ips(local_ips)

    if not packets:
        return {
            "packet_count": 0,
            "byte_count": 0,
            "avg_packet_size": 0.0,
            "tcp_count": 0,
            "udp_count": 0,
            "icmp_count": 0,
            "unique_src_ips": 0,
            "unique_dst_ips": 0,
            "unique_host_pairs": 0,
            "unique_service_ports": 0,
            "new_connection_count": 0,
            "avg_connection_duration": 0.0,
            "max_connection_duration": 0.0,
            "avg_inter_arrival_ms": 0.0,
            "max_packets_per_src": 0,
            "avg_packets_per_src": 0.0,
            "avg_bytes_per_src": 0.0,
            "inbound_packet_count": 0,
            "outbound_packet_count": 0,
            "inbound_byte_count": 0,
            "outbound_byte_count": 0,
            "top_src_ips": [],
        }

    ordered_packets = sorted(packets, key=lambda packet: float(packet["timestamp"]))
    timestamps = [float(packet["timestamp"]) for packet in ordered_packets]
    protocol_counts = Counter(str(packet["protocol"]) for packet in ordered_packets)
    source_counts = Counter(str(packet["src_ip"]) for packet in ordered_packets)
    source_bytes = Counter()
    host_pairs = set()
    service_ports = set()
    flow_times: dict[tuple[str, str, str, int | None, int | None], list[float]] = defaultdict(list)

    byte_count = 0
    inbound_packet_count = 0
    outbound_packet_count = 0
    inbound_byte_count = 0
    outbound_byte_count = 0

    for packet in ordered_packets:
        src_ip = str(packet["src_ip"])
        dst_ip = str(packet["dst_ip"])
        protocol = str(packet["protocol"])
        src_port = _safe_int(packet.get("src_port"))
        dst_port = _safe_int(packet.get("dst_port"))
        size = int(packet["size"])
        timestamp = float(packet["timestamp"])

        byte_count += size
        source_bytes[src_ip] += size
        host_pairs.add((src_ip, dst_ip))

        if dst_port is not None:
            service_ports.add(dst_port)

        flow_key = (src_ip, dst_ip, protocol, src_port, dst_port)
        flow_times[flow_key].append(timestamp)

        if tracked_local_ips:
            if dst_ip in tracked_local_ips and src_ip not in tracked_local_ips:
                inbound_packet_count += 1
                inbound_byte_count += size
            elif src_ip in tracked_local_ips and dst_ip not in tracked_local_ips:
                outbound_packet_count += 1
                outbound_byte_count += size

    inter_arrival_ms = [
        round((timestamps[index] - timestamps[index - 1]) * 1000.0, 3)
        for index in range(1, len(timestamps))
    ]
    flow_durations = [round(max(times) - min(times), 6) for times in flow_times.values()]
    packet_count = len(ordered_packets)
    avg_packet_size = round(byte_count / packet_count, 2)

    return {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "avg_packet_size": avg_packet_size,
        "tcp_count": protocol_counts["TCP"],
        "udp_count": protocol_counts["UDP"],
        "icmp_count": protocol_counts["ICMP"],
        "unique_src_ips": len(source_counts),
        "unique_dst_ips": len({str(packet["dst_ip"]) for packet in ordered_packets}),
        "unique_host_pairs": len(host_pairs),
        "unique_service_ports": len(service_ports),
        "new_connection_count": len(flow_times),
        "avg_connection_duration": round(mean(flow_durations), 6) if flow_durations else 0.0,
        "max_connection_duration": round(max(flow_durations), 6) if flow_durations else 0.0,
        "avg_inter_arrival_ms": round(mean(inter_arrival_ms), 3) if inter_arrival_ms else 0.0,
        "max_packets_per_src": max(source_counts.values()),
        "avg_packets_per_src": round(mean(source_counts.values()), 3),
        "avg_bytes_per_src": round(mean(source_bytes.values()), 3),
        "inbound_packet_count": inbound_packet_count,
        "outbound_packet_count": outbound_packet_count,
        "inbound_byte_count": inbound_byte_count,
        "outbound_byte_count": outbound_byte_count,
        "top_src_ips": source_counts.most_common(5),
    }


def _iter_window_records(
    packet_records: Iterable[dict[str, object]],
    window_size: int,
    local_ips: Iterable[str] | None = None,
) -> list[dict[str, object]]:
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
        feature_row = packets_to_features(window_packets, local_ips=local_ips)
        feature_row["window_id"] = window_id
        feature_row["window_start"] = round(first_timestamp + (window_id * window_size), 3)
        rows.append(feature_row)
    return rows


def windowed_features_from_csv(
    csv_path: str,
    window_size: int = WINDOW_SECONDS,
    local_ips: Iterable[str] | None = None,
) -> pd.DataFrame:
    """Convert a raw packet CSV into one feature row per time window."""
    packet_df = pd.read_csv(csv_path)
    if packet_df.empty:
        raise ValueError(f"No packet data found in {csv_path}")

    required = {"timestamp", "src_ip", "dst_ip", "size", "protocol"}
    missing = sorted(required.difference(packet_df.columns))
    if missing:
        raise ValueError(f"Packet CSV missing required columns: {missing}")

    for optional_column in ["src_port", "dst_port"]:
        if optional_column not in packet_df.columns:
            packet_df[optional_column] = None

    rows = _iter_window_records(packet_df.to_dict("records"), window_size, local_ips=local_ips)
    feature_df = pd.DataFrame(rows)
    if feature_df.empty:
        raise ValueError(f"No feature windows could be generated from {csv_path}")

    ordered_columns = ["window_id", "window_start", *FEATURE_COLS, "top_src_ips"]
    return feature_df[ordered_columns]


def live_windows(
    window_size: int = WINDOW_SECONDS,
    local_ips: Iterable[str] | None = None,
):
    """Yield one feature dict for each completed live capture window."""
    current_window_start = time.time()
    current_window_end = current_window_start + window_size
    buffer: list[dict[str, object]] = []

    while True:
        timeout = max(0.0, current_window_end - time.time())

        if timeout == 0.0:
            feature_row = packets_to_features(buffer, local_ips=local_ips)
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
                feature_row = packets_to_features(buffer, local_ips=local_ips)
                feature_row["window_start"] = round(current_window_start, 3)
                yield feature_row
                buffer = []
                current_window_start = current_window_end
                current_window_end = current_window_start + window_size

            buffer.append(packet)
        except queue.Empty:
            feature_row = packets_to_features(buffer, local_ips=local_ips)
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
    parser.add_argument(
        "--local-ip",
        action="append",
        default=[],
        help="Local IP to use for inbound/outbound feature calculation; repeat for multiple IPs",
    )
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    local_ips = args.local_ip or sorted(default_local_ips())
    frame = windowed_features_from_csv(args.input, window_size=args.window, local_ips=local_ips)
    frame.to_csv(args.output, index=False)
    print(f"[features] Wrote {len(frame)} feature windows to {args.output}")
