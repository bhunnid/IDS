"""
train.py — Train an Isolation Forest on NORMAL traffic.

Responsibilities:
  - Load a feature CSV produced by features.py
  - Fit a StandardScaler (removes feature-scale bias)
  - Fit an Isolation Forest on the scaled features
  - Save both artefacts to disk

Architecture notes:
  - No imports from any other IDS module — fully standalone
  - FEATURE_COLS is imported from features.py so column order is
    defined in exactly one place

Why scale features?
  Raw features span very different magnitudes:
    total_bytes   → hundreds of thousands
    icmp_count    → single digits
  Without scaling, Isolation Forest trees split almost exclusively on
  total_bytes and effectively ignore icmp_count.  StandardScaler maps
  every feature to mean=0, std=1 before training so each feature has
  equal influence on the tree splits.

Contamination guide (--contamination flag):
  0.01 → very strict: few false positives, may miss subtle attacks
  0.05 → balanced default
  0.10 → permissive: higher recall, noisier in clean traffic

Usage:
    # 1. Capture normal traffic
    python capture.py --save normal.csv

    # 2. Extract features
    python features.py --input normal.csv --output normal_features.csv

    # 3. Train
    python train.py --input normal_features.csv
    python train.py --input normal_features.csv --contamination 0.01
    python train.py --input normal_features.csv --model my_model.pkl --scaler my_scaler.pkl
"""

import argparse

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Import ONLY the column list — no circular risk
from features import FEATURE_COLS

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_MODEL_PATH  = "ids_model.pkl"
DEFAULT_SCALER_PATH = "scaler.pkl"
DEFAULT_CONTAMINATION = 0.05


# ── Training ──────────────────────────────────────────────────────────────────

def train(
    features_csv:  str,
    model_path:    str   = DEFAULT_MODEL_PATH,
    scaler_path:   str   = DEFAULT_SCALER_PATH,
    contamination: float = DEFAULT_CONTAMINATION,
) -> None:
    """
    Load features, fit scaler + model, save both to disk.

    Prints a training report including:
      - per-feature raw statistics (for report)
      - anomaly score range on training data
      - number of training windows flagged
    """
    # ── Load data ─────────────────────────────────────────────────────────────
    df = pd.read_csv(features_csv)
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise ValueError(
            f"Feature CSV is missing columns: {missing}\n"
            f"Expected: {FEATURE_COLS}\n"
            f"Got:      {list(df.columns)}"
        )

    X = df[FEATURE_COLS].to_numpy(dtype=float)
    print(f"[train] {len(X)} windows loaded from {features_csv}")
    print(f"[train] contamination = {contamination}\n")

    # ── Feature statistics (useful in report) ─────────────────────────────────
    print("[train] Raw feature statistics:")
    header = f"  {'feature':<16}  {'mean':>12}  {'std':>12}  {'min':>10}  {'max':>10}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for i, col in enumerate(FEATURE_COLS):
        col_data = X[:, i]
        print(
            f"  {col:<16}  {col_data.mean():>12.2f}  {col_data.std():>12.2f}"
            f"  {col_data.min():>10.2f}  {col_data.max():>10.2f}"
        )

    # ── Fit scaler ────────────────────────────────────────────────────────────
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    print(f"\n[train] StandardScaler fitted — features scaled to mean≈0, std≈1")

    # ── Fit model ─────────────────────────────────────────────────────────────
    print(f"[train] Training IsolationForest (n_estimators=100) ...")
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,   # reproducible; same seed → same model every run
        n_jobs=-1,         # use all CPU cores during training only
    )
    model.fit(X_scaled)

    # ── Training report ───────────────────────────────────────────────────────
    scores      = model.decision_function(X_scaled)
    predictions = model.predict(X_scaled)          # 1=normal, -1=anomaly
    n_anomalies = int((predictions == -1).sum())
    pct         = n_anomalies / len(X) * 100

    print(f"\n[train] Score range on training data: [{scores.min():.4f}, {scores.max():.4f}]")
    print(f"[train] Decision boundary: 0.0  (scores below threshold → ALERT)")
    print(f"[train] Flagged in training: {n_anomalies}/{len(X)} ({pct:.1f}%)")

    if pct > 15:
        print(
            "[train] WARNING: >15% of training windows flagged.\n"
            "         Consider capturing more normal traffic or lowering --contamination."
        )

    # ── Save artefacts ────────────────────────────────────────────────────────
    joblib.dump(model,  model_path)
    joblib.dump(scaler, scaler_path)
    print(f"\n[train] Model  saved → {model_path}")
    print(f"[train] Scaler saved → {scaler_path}")
    print("[train] Done.")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train IDS Isolation Forest model")
    parser.add_argument("--input",         required=True,
                        metavar="CSV",     help="Features CSV from features.py")
    parser.add_argument("--model",         default=DEFAULT_MODEL_PATH,
                        metavar="PKL",     help=f"Model output path (default: {DEFAULT_MODEL_PATH})")
    parser.add_argument("--scaler",        default=DEFAULT_SCALER_PATH,
                        metavar="PKL",     help=f"Scaler output path (default: {DEFAULT_SCALER_PATH})")
    parser.add_argument("--contamination", default=DEFAULT_CONTAMINATION, type=float,
                        metavar="FLOAT",   help=f"Fraction of anomalies in training data "
                                                f"(default: {DEFAULT_CONTAMINATION})")
    args = parser.parse_args()

    train(
        features_csv  = args.input,
        model_path    = args.model,
        scaler_path   = args.scaler,
        contamination = args.contamination,
    )
