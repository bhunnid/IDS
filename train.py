"""Model training for the lightweight anomaly-based IDS."""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from features import FEATURE_COLS

DEFAULT_MODEL_PATH = "ids_model.pkl"
DEFAULT_SCALER_PATH = "scaler.pkl"
DEFAULT_CONTAMINATION = 0.05
RANDOM_STATE = 42


def train(
    features_csv: str,
    model_path: str = DEFAULT_MODEL_PATH,
    scaler_path: str = DEFAULT_SCALER_PATH,
    contamination: float = DEFAULT_CONTAMINATION,
) -> None:
    """Train a scaler and IsolationForest from a features CSV."""
    if not 0.0 < contamination < 0.5:
        raise ValueError("contamination must be greater than 0.0 and less than 0.5")

    frame = pd.read_csv(features_csv)
    missing = [column for column in FEATURE_COLS if column not in frame.columns]
    if missing:
        raise ValueError(f"Feature CSV missing required columns: {missing}")
    if frame.empty:
        raise ValueError("Feature CSV is empty")

    train_matrix = frame[FEATURE_COLS].astype(float)

    scaler = StandardScaler()
    scaled = scaler.fit_transform(train_matrix)

    model = IsolationForest(
        contamination=contamination,
        n_estimators=200,
        random_state=RANDOM_STATE,
        n_jobs=1,
    )
    model.fit(scaled)

    model_scores = model.decision_function(scaled)
    predicted_anomalies = int((model_scores < 0.0).sum())

    model_target = Path(model_path)
    scaler_target = Path(scaler_path)
    model_target.parent.mkdir(parents=True, exist_ok=True)
    scaler_target.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_target)
    joblib.dump(scaler, scaler_target)

    print(f"[train] Loaded {len(frame)} windows from {features_csv}")
    print(f"[train] Contamination: {contamination:.2f}")
    print(f"[train] Score range: {model_scores.min():+.4f} to {model_scores.max():+.4f}")
    print(f"[train] Training-set anomalies at score<0.0: {predicted_anomalies}/{len(frame)}")
    print(f"[train] Saved model to {model_target}")
    print(f"[train] Saved scaler to {scaler_target}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train the IDS anomaly detection model")
    parser.add_argument("--input", required=True, help="Feature CSV created by features.py")
    parser.add_argument("--model", default=DEFAULT_MODEL_PATH, help="Output path for ids_model.pkl")
    parser.add_argument("--scaler", default=DEFAULT_SCALER_PATH, help="Output path for scaler.pkl")
    parser.add_argument(
        "--contamination",
        type=float,
        default=DEFAULT_CONTAMINATION,
        help=f"IsolationForest contamination value (default: {DEFAULT_CONTAMINATION})",
    )
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    train(
        features_csv=args.input,
        model_path=args.model,
        scaler_path=args.scaler,
        contamination=args.contamination,
    )
