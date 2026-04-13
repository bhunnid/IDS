"""Formal evaluation utilities for labeled IDS feature datasets."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_score,
    recall_score,
    roc_auc_score,
)

from detect import load_artifacts
from features import FEATURE_COLS

DEFAULT_LABEL_COLUMN = "label"


def _normalize_label(value: object) -> int:
    text = str(value).strip().lower()
    if text in {"1", "true", "attack", "anomaly", "malicious", "alert"}:
        return 1
    if text in {"0", "false", "normal", "benign"}:
        return 0
    raise ValueError(
        f"Unsupported label value '{value}'. Use one of: normal/benign/0 or anomaly/attack/1."
    )


def _score_frame(model, scaler, frame: pd.DataFrame) -> pd.DataFrame:
    feature_matrix = frame[FEATURE_COLS].astype(float)
    scaled = scaler.transform(feature_matrix)
    scores = model.decision_function(scaled)
    scored = frame.copy()
    scored["score"] = scores
    return scored


def evaluate_threshold(scored_frame: pd.DataFrame, threshold: float) -> dict[str, float]:
    predicted = (scored_frame["score"] < threshold).astype(int)
    actual = scored_frame["binary_label"].astype(int)

    tn, fp, fn, tp = confusion_matrix(actual, predicted, labels=[0, 1]).ravel()
    precision = precision_score(actual, predicted, zero_division=0)
    recall = recall_score(actual, predicted, zero_division=0)
    accuracy = accuracy_score(actual, predicted)
    f1 = 0.0 if (precision + recall) == 0 else (2 * precision * recall) / (precision + recall)
    false_positive_rate = 0.0 if (fp + tn) == 0 else fp / (fp + tn)
    false_negative_rate = 0.0 if (fn + tp) == 0 else fn / (fn + tp)

    return {
        "threshold": threshold,
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(false_positive_rate), 4),
        "false_negative_rate": round(float(false_negative_rate), 4),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
    }


def evaluate_dataset(
    features_csv: str,
    model_path: str,
    scaler_path: str,
    threshold: float,
    label_column: str = DEFAULT_LABEL_COLUMN,
    sweep: list[float] | None = None,
    metrics_output: str | None = None,
    scored_output: str | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Evaluate a labeled feature CSV against the trained detector."""
    frame = pd.read_csv(features_csv)
    missing = [column for column in FEATURE_COLS if column not in frame.columns]
    if missing:
        raise ValueError(f"Evaluation CSV missing required feature columns: {missing}")
    if label_column not in frame.columns:
        raise ValueError(f"Evaluation CSV missing label column '{label_column}'")

    frame["binary_label"] = frame[label_column].apply(_normalize_label)
    model, scaler = load_artifacts(model_path, scaler_path)
    scored_frame = _score_frame(model, scaler, frame)

    thresholds = [threshold]
    if sweep:
        thresholds.extend(sweep)
    thresholds = list(dict.fromkeys(thresholds))

    metrics_rows = [evaluate_threshold(scored_frame, current_threshold) for current_threshold in thresholds]
    metrics_frame = pd.DataFrame(metrics_rows).sort_values("threshold").reset_index(drop=True)

    if scored_frame["binary_label"].nunique() == 2:
        roc_auc = roc_auc_score(scored_frame["binary_label"], -scored_frame["score"])
        metrics_frame["roc_auc"] = round(float(roc_auc), 4)
    else:
        metrics_frame["roc_auc"] = float("nan")

    if metrics_output:
        metrics_target = Path(metrics_output)
        metrics_target.parent.mkdir(parents=True, exist_ok=True)
        metrics_frame.to_csv(metrics_target, index=False)

    if scored_output:
        scored_target = Path(scored_output)
        scored_target.parent.mkdir(parents=True, exist_ok=True)
        scored_frame.to_csv(scored_target, index=False)

    return metrics_frame, scored_frame


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate IDS predictions on labeled feature data")
    parser.add_argument("--input", required=True, help="Labeled feature CSV")
    parser.add_argument("--model", default="ids_model.pkl", help="Path to trained model")
    parser.add_argument("--scaler", default="scaler.pkl", help="Path to trained scaler")
    parser.add_argument("--threshold", type=float, default=-0.10, help="Primary alert threshold")
    parser.add_argument(
        "--label-column",
        default=DEFAULT_LABEL_COLUMN,
        help=f"Column containing ground-truth labels (default: {DEFAULT_LABEL_COLUMN})",
    )
    parser.add_argument(
        "--sweep",
        type=float,
        nargs="*",
        default=[],
        help="Optional extra thresholds to evaluate in one run",
    )
    parser.add_argument("--metrics-out", help="Optional CSV output path for evaluation metrics")
    parser.add_argument("--scored-out", help="Optional CSV output path for per-row scores")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    metrics_frame, _ = evaluate_dataset(
        features_csv=args.input,
        model_path=args.model,
        scaler_path=args.scaler,
        threshold=args.threshold,
        label_column=args.label_column,
        sweep=args.sweep,
        metrics_output=args.metrics_out,
        scored_output=args.scored_out,
    )
    print(metrics_frame.to_string(index=False))
