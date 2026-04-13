"""
features.py — Feature extraction from raw packet streams.

Responsibilities:
  - Aggregate packets into fixed time windows
  - Compute ML feature vectors from each window
  - Provide a generator that yields one feature dict per window

Architecture notes:
  - Pure functions: packets_to_features() has no side effects
  - Window generator reads from pipeline.PACKET_QUEUE — not from capture.py
  - Window boundaries are clock-anchored (never drift)
  - An empty window still yields a zeroed vector (silence is a signal)

Feature schema (8 numeric features, all non-negative):
    packet_count   int    — packets seen in the window
    avg_pkt_size   float  — mean packet size in bytes
    total_bytes    int    — sum of all packet sizes
    unique_ips     int    — distinct src + dst IPs seen
    tcp_count      int    — TCP packets
    udp_count      int    — UDP packets
    icmp_count     int    — ICMP packets
    other_count    int    — all other protocols

Usage (offline — process a CSV produced by capture.py):
    python features.py --input training_data.csv --output features.csv
    python features.py --input training_data.csv --output features.csv --window 5
"""

import argparse
import time
from collections import Counter

import pandas as pd

from pipeline import PACKET_QUEUE

# ── Constants ─────────────────────────────────────────────────────────────────

# Window length in seconds.  Change here; every module that imports
# WINDOW_SECONDS will automatically use the updated value.
WINDOW_SECONDS: int = 10

# Canonical feature column order.  train.py and detect.py both import this
# so the column order is defined exactly once.
FEATURE_COLS: list[str] = [
    "packet_count",
    "avg_pkt_size",
    "total_bytes",
    "unique_ips",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "other_count",
]

# A zeroed feature vector returned for empty windows
_ZERO_FEATURES: dict = {col: 0 for col in FEATURE_COLS}
_ZERO_FEATURES["avg_pkt_size"] = 0.0


# ── Core feature computation ──────────────────────────────────────────────────

def packets_to_features(packets: list[dict]) -> dict:
    """
    Compute a feature vector from a list of packet dicts.

    This is a pure function — no globals, no side effects.
    Returns a dict whose keys exactly match FEATURE_COLS.

    Args:
        packets: list of dicts from parse_packet() (may be empty)
    """
    if not packets:
        return dict(_ZERO_FEATURES)   # return a copy so callers can't mutate it

    sizes     = [p["size"] for p in packets]
    protocols = Counter(p["protocol"] for p in packets)

    unique_ips = len(
        {p["src_ip"] for p in packets} | {p["dst_ip"] for p in packets}
    )

    return {
        "packet_count": len(packets),
        "avg_pkt_size": round(sum(sizes) / len(sizes), 2),
        "total_bytes":  sum(sizes),
        "unique_ips":   unique_ips,
        "tcp_count":    protocols["TCP"],
        "udp_count":    protocols["UDP"],
        "icmp_count":   protocols["ICMP"],
        "other_count":  protocols["OTHER"],
    }


# ── Offline CSV processing ────────────────────────────────────────────────────

def windowed_features_from_csv(csv_path: str,
                                window_sec: int = WINDOW_SECONDS) -> pd.DataFrame:
    """
    Read a packet CSV (from capture.py --save) and return a DataFrame
    of feature vectors, one row per time window.

    Packets are bucketed into windows using integer division of their
    offset from the earliest timestamp — so windows are always the
    same size regardless of packet arrival gaps.
    """
    df = pd.read_csv(csv_path)
    if df.empty:
        raise ValueError(f"No data in {csv_path}")

    df["timestamp"] = df["timestamp"].astype(float)
    t_min = df["timestamp"].min()
    df["_window"] = ((df["timestamp"] - t_min) // window_sec).astype(int)

    rows = []
    for win_id, group in df.groupby("_window"):
        feat = packets_to_features(group.to_dict("records"))
        feat["window_id"]    = int(win_id)
        feat["window_start"] = round(t_min + win_id * window_sec, 3)
        rows.append(feat)

    cols = ["window_id", "window_start"] + FEATURE_COLS
    return pd.DataFrame(rows)[cols]


# ── Live window generator ─────────────────────────────────────────────────────

def live_windows(window_sec: int = WINDOW_SECONDS):
    """
    Generator that reads from pipeline.PACKET_QUEUE and yields one feature
    dict per completed time window.

    Window timing is clock-anchored:
      - window_end = window_start + window_sec  (fixed at window open time)
      - next window_start = previous window_end  (never re-reads the clock)
    This means windows never drift even if inference takes significant time.

    Each yielded dict contains:
      - all keys from FEATURE_COLS
      - "window_start"  float  — epoch time of window start
      - "top_src_ips"   list   — [(ip, count), ...] top 3 source IPs

    Yields immediately when the clock crosses window_end, even if the
    queue is empty (zero-packet window → zeroed feature vector).
    """
    buffer: list[dict] = []
    window_start = time.time()
    window_end   = window_start + window_sec

    while True:
        # ── Drain queue ───────────────────────────────────────────────────────
        # Empty the queue without blocking so we never stall here.
        # get_nowait() raises queue.Empty when the queue is exhausted.
        try:
            while True:
                buffer.append(PACKET_QUEUE.get_nowait())
        except Exception:
            pass   # queue.Empty — that's fine, just means we've drained it

        # ── Check window boundary ─────────────────────────────────────────────
        now = time.time()
        if now >= window_end:
            feat = packets_to_features(buffer)
            feat["window_start"] = round(window_start, 3)

            # Top-3 source IPs for this window (used by detect.py on ANOMALY)
            src_counts = Counter(p["src_ip"] for p in buffer)
            feat["top_src_ips"] = src_counts.most_common(3)

            # Advance boundary by exactly window_sec — no clock re-read
            window_start = window_end
            window_end   = window_start + window_sec
            buffer       = []

            yield feat
        else:
            # Sleep until the window ends, but cap at 200 ms so we stay
            # responsive to packets without busy-waiting.
            time.sleep(min(0.2, window_end - now))


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract flow features from a captured packet CSV"
    )
    parser.add_argument("--input",  required=True,  metavar="CSV",
                        help="Packet CSV from capture.py --save")
    parser.add_argument("--output", required=True,  metavar="CSV",
                        help="Output features CSV")
    parser.add_argument("--window", type=int, default=WINDOW_SECONDS,
                        help=f"Window size in seconds (default: {WINDOW_SECONDS})")
    args = parser.parse_args()

    print(f"[features] Processing {args.input} with {args.window}s windows ...")
    feat_df = windowed_features_from_csv(args.input, args.window)
    feat_df.to_csv(args.output, index=False)
    print(f"[features] {len(feat_df)} windows → {args.output}")
    print(feat_df.to_string(index=False))
