"""Dataset preparation helpers for IDS evaluation workflows."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

DEFAULT_LABEL_COLUMN = "label"
DEFAULT_SCENARIO_COLUMN = "scenario"
DEFAULT_SOURCE_COLUMN = "source_file"


def label_features(
    input_csv: str,
    output_csv: str,
    label: str,
    scenario: str,
    label_column: str = DEFAULT_LABEL_COLUMN,
    scenario_column: str = DEFAULT_SCENARIO_COLUMN,
    source_column: str = DEFAULT_SOURCE_COLUMN,
) -> pd.DataFrame:
    """Apply a ground-truth label and scenario tag to a feature CSV."""
    frame = pd.read_csv(input_csv)
    if frame.empty:
        raise ValueError(f"Feature CSV is empty: {input_csv}")

    frame[label_column] = label
    frame[scenario_column] = scenario
    frame[source_column] = Path(input_csv).name

    output_path = Path(output_csv)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output_path, index=False)
    return frame


def merge_datasets(
    inputs: list[str],
    output_csv: str,
    deduplicate: bool = False,
) -> pd.DataFrame:
    """Merge multiple labeled feature CSVs into one evaluation dataset."""
    if not inputs:
        raise ValueError("At least one input CSV is required")

    frames = []
    for csv_path in inputs:
        frame = pd.read_csv(csv_path)
        if frame.empty:
            continue
        if DEFAULT_SOURCE_COLUMN not in frame.columns:
            frame[DEFAULT_SOURCE_COLUMN] = Path(csv_path).name
        frames.append(frame)

    if not frames:
        raise ValueError("No rows were loaded from the provided CSV files")

    merged = pd.concat(frames, ignore_index=True)
    if deduplicate:
        merged = merged.drop_duplicates().reset_index(drop=True)

    output_path = Path(output_csv)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    merged.to_csv(output_path, index=False)
    return merged


def dataset_summary(input_csv: str) -> dict[str, object]:
    """Return a compact summary of a labeled evaluation dataset."""
    frame = pd.read_csv(input_csv)
    if frame.empty:
        raise ValueError(f"Dataset is empty: {input_csv}")

    summary: dict[str, object] = {
        "rows": int(len(frame)),
        "columns": list(frame.columns),
    }

    if DEFAULT_LABEL_COLUMN in frame.columns:
        summary["label_counts"] = frame[DEFAULT_LABEL_COLUMN].value_counts().to_dict()
    if DEFAULT_SCENARIO_COLUMN in frame.columns:
        summary["scenario_counts"] = frame[DEFAULT_SCENARIO_COLUMN].value_counts().to_dict()

    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare labeled IDS evaluation datasets")
    subparsers = parser.add_subparsers(dest="command", required=True)

    label_parser = subparsers.add_parser("label", help="Apply a label and scenario tag to a feature CSV")
    label_parser.add_argument("--input", required=True, help="Feature CSV to label")
    label_parser.add_argument("--output", required=True, help="Output labeled CSV")
    label_parser.add_argument("--label", required=True, help="Ground-truth label, for example normal or attack")
    label_parser.add_argument("--scenario", required=True, help="Scenario tag, for example nmap_scan")
    label_parser.add_argument("--label-column", default=DEFAULT_LABEL_COLUMN, help="Label column name")
    label_parser.add_argument("--scenario-column", default=DEFAULT_SCENARIO_COLUMN, help="Scenario column name")

    merge_parser = subparsers.add_parser("merge", help="Merge multiple labeled CSVs")
    merge_parser.add_argument("--inputs", nargs="+", required=True, help="Input labeled CSVs")
    merge_parser.add_argument("--output", required=True, help="Output merged CSV")
    merge_parser.add_argument("--deduplicate", action="store_true", help="Drop duplicate rows after merge")

    summary_parser = subparsers.add_parser("summary", help="Show dataset label and scenario counts")
    summary_parser.add_argument("--input", required=True, help="Merged labeled dataset CSV")

    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.command == "label":
        frame = label_features(
            input_csv=args.input,
            output_csv=args.output,
            label=args.label,
            scenario=args.scenario,
            label_column=args.label_column,
            scenario_column=args.scenario_column,
        )
        print(f"Labeled {len(frame)} rows -> {args.output}")
    elif args.command == "merge":
        frame = merge_datasets(inputs=args.inputs, output_csv=args.output, deduplicate=args.deduplicate)
        print(f"Merged {len(frame)} rows -> {args.output}")
    else:
        summary = dataset_summary(args.input)
        print(summary)
