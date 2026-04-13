"""
train.py — Train an Isolation Forest model on NORMAL traffic only.
Saves both the trained model and a fitted StandardScaler to disk.

Why scale features?
    Features like total_bytes (thousands) and icmp_count (single digits)
    live on very different scales. Without scaling, Isolation Forest
    implicitly weights high-magnitude features more heavily, which can
    cause it to miss anomalies in low-magnitude dimensions entirely.
    StandardScaler brings every feature to mean=0, std=1 before training.

How Isolation Forest works (simple explanation):
    - Randomly partitions the feature space using decision trees.
    - Anomalies are isolated (split off) quickly because they're sparse
      or unusual — short path length through the trees = anomaly.
    - Score < 0 → anomaly. Score > 0 → normal.

Contamination guide (tune this for your report):
    0.01 → very strict — few false positives, may miss subtle attacks
    0.05 → balanced default — good starting point
    0.10 → permissive  — catches more, but noisier

Usage:
    python capture.py --save normal_traffic.csv
    python features.py --input normal_traffic.csv --output normal_features.csv
    python train.py --input normal_features.csv --model ids_model.pkl
    → Also saves scaler.pkl alongside the model automatically.
"""

import argparse

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Columns used as model inputs — must match what features.py produces
FEATURE_COLS = [
    "packet_count",
    "avg_pkt_size",
    "total_bytes",
    "unique_ips",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "other_count",
]

# Default scaler output path — detect.py loads this automatically
SCALER_PATH = "scaler.pkl"

# Contamination: estimated fraction of anomalies in training data.
CONTAMINATION = 0.05


def train(features_csv: str, model_path: str,
          contamination: float = CONTAMINATION,
          scaler_path: str = SCALER_PATH):
    """Load feature CSV, scale features, fit Isolation Forest, save both artifacts."""
    df = pd.read_csv(features_csv)

    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns in input CSV: {missing}")

    X = df[FEATURE_COLS].values
    print(f"[train] Loaded {len(X)} feature windows from {features_csv}")
    print(f"[train] Contamination rate: {contamination}\n")

    # ── Feature scaling ────────────────────────────────────────────────────────
    # Fit scaler on training data only; detect.py applies the same transform
    # at inference time so the model always sees the same feature distribution.
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Show what scaling did — useful for your report
    print("[train] Feature statistics after scaling (mean≈0, std≈1):")
    for i, col in enumerate(FEATURE_COLS):
        raw_mean = X[:, i].mean()
        raw_std  = X[:, i].std()
        print(f"         {col:<16s}  raw mean={raw_mean:>10.2f}  raw std={raw_std:>10.2f}")

    # ── Model training ─────────────────────────────────────────────────────────
    print(f"\n[train] Training Isolation Forest (n_estimators=100, contamination={contamination})...")
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,    # reproducible — same seed = same model every run
        n_jobs=-1,          # use all CPU cores
    )
    model.fit(X_scaled)
    print("[train] Training complete.")

    # ── Sanity check on training data ─────────────────────────────────────────
    scores      = model.decision_function(X_scaled)
    predictions = model.predict(X_scaled)          # 1=normal, -1=anomaly
    n_anomalies = (predictions == -1).sum()

    print(f"\n[train] Anomaly score range: [{scores.min():.4f}, {scores.max():.4f}]")
    print(f"[train] Decision boundary  : 0.0  (below = anomaly)")
    print(f"[train] Windows flagged    : {n_anomalies}/{len(X)} "
          f"({n_anomalies / len(X) * 100:.1f}%)")

    if n_anomalies / len(X) > 0.15:
        print("[train] WARNING: >15% of training windows flagged — consider "
              "lowering --contamination or capturing cleaner baseline traffic.")

    # ── Persist artifacts ─────────────────────────────────────────────────────
    joblib.dump(model,  model_path)
    joblib.dump(scaler, scaler_path)
    print(f"\n[train] Model  saved → {model_path}")
    print(f"[train] Scaler saved → {scaler_path}")


# ── CLI entry point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train IDS anomaly detection model")
    parser.add_argument("--input",         required=True,       metavar="CSV",
                        help="Features CSV from features.py")
    parser.add_argument("--model",         default="ids_model.pkl", metavar="PKL",
                        help="Output model file (default: ids_model.pkl)")
    parser.add_argument("--scaler",        default=SCALER_PATH, metavar="PKL",
                        help=f"Output scaler file (default: {SCALER_PATH})")
    parser.add_argument("--contamination", type=float, default=CONTAMINATION,
                        help=f"Fraction of anomalies in training data (default: {CONTAMINATION})")
    args = parser.parse_args()

    train(args.input, args.model, args.contamination, args.scaler)
