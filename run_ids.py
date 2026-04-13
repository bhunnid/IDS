"""Single CLI entry point for the lightweight anomaly-based IDS."""

from __future__ import annotations

import argparse


def cmd_capture(args) -> None:
    from capture import list_interfaces, start_capture

    if args.list_ifaces:
        for name in list_interfaces():
            print(name)
        return

    start_capture(iface=args.iface, save_path=args.save, verbose=args.verbose)


def cmd_features(args) -> None:
    from features import default_local_ips, windowed_features_from_csv

    local_ips = args.local_ip or sorted(default_local_ips())
    frame = windowed_features_from_csv(args.input, window_size=args.window, local_ips=local_ips)
    frame.to_csv(args.output, index=False)
    print(f"[run_ids] Wrote {len(frame)} windows to {args.output}")


def cmd_train(args) -> None:
    from train import train

    train(
        features_csv=args.input,
        model_path=args.model,
        scaler_path=args.scaler,
        contamination=args.contamination,
    )


def cmd_live(args) -> None:
    from detect import load_artifacts, run_live
    from features import default_local_ips

    model, scaler = load_artifacts(args.model, args.scaler)
    local_ips = args.local_ip or sorted(default_local_ips())
    run_live(
        model,
        scaler,
        threshold=args.threshold,
        iface=args.iface,
        window_size=args.window,
        log_path=args.log,
        local_ips=local_ips,
    )


def cmd_replay(args) -> None:
    from detect import load_artifacts, run_replay

    model, scaler = load_artifacts(args.model, args.scaler)
    run_replay(
        model,
        scaler,
        features_csv=args.input,
        threshold=args.threshold,
        log_path=args.log,
    )


def cmd_evaluate(args) -> None:
    from evaluate import evaluate_dataset

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


def cmd_label_dataset(args) -> None:
    from dataset import label_features

    frame = label_features(
        input_csv=args.input,
        output_csv=args.output,
        label=args.label,
        scenario=args.scenario,
        label_column=args.label_column,
        scenario_column=args.scenario_column,
    )
    print(f"[run_ids] Labeled {len(frame)} rows -> {args.output}")


def cmd_merge_datasets(args) -> None:
    from dataset import merge_datasets

    frame = merge_datasets(
        inputs=args.inputs,
        output_csv=args.output,
        deduplicate=args.deduplicate,
    )
    print(f"[run_ids] Merged {len(frame)} rows -> {args.output}")


def cmd_dataset_summary(args) -> None:
    from dataset import dataset_summary

    summary = dataset_summary(args.input)
    print(summary)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_ids.py",
        description="Lightweight anomaly-based IDS for Windows",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture_parser = subparsers.add_parser("capture", help="Capture packet metadata to CSV")
    capture_parser.add_argument("--save", help="Optional packet CSV output path")
    capture_parser.add_argument("--iface", help="Interface name such as 'Wi-Fi' or 'Ethernet'")
    capture_parser.add_argument("--verbose", action="store_true", help="Print captured packets")
    capture_parser.add_argument("--list-ifaces", action="store_true", help="List interfaces and exit")
    capture_parser.set_defaults(func=cmd_capture)

    features_parser = subparsers.add_parser("features", help="Extract feature windows from packet CSV")
    features_parser.add_argument("--input", required=True, help="Raw packet CSV from capture")
    features_parser.add_argument("--output", required=True, help="Output feature CSV path")
    features_parser.add_argument("--window", type=int, default=10, help="Window size in seconds")
    features_parser.add_argument(
        "--local-ip",
        action="append",
        default=[],
        help="Local IP to use for inbound/outbound features; repeat for multiple IPs",
    )
    features_parser.set_defaults(func=cmd_features)

    train_parser = subparsers.add_parser("train", help="Train the anomaly detection model")
    train_parser.add_argument("--input", required=True, help="Feature CSV from the features command")
    train_parser.add_argument("--model", default="ids_model.pkl", help="Model output path")
    train_parser.add_argument("--scaler", default="scaler.pkl", help="Scaler output path")
    train_parser.add_argument("--contamination", type=float, default=0.05, help="IsolationForest contamination")
    train_parser.set_defaults(func=cmd_train)

    live_parser = subparsers.add_parser("live", help="Start live packet capture and anomaly detection")
    live_parser.add_argument("--model", default="ids_model.pkl", help="Path to trained model")
    live_parser.add_argument("--scaler", default="scaler.pkl", help="Path to trained scaler")
    live_parser.add_argument("--iface", help="Interface name such as 'Wi-Fi' or 'Ethernet'")
    live_parser.add_argument("--window", type=int, default=10, help="Window size in seconds")
    live_parser.add_argument("--threshold", type=float, default=-0.10, help="Alert threshold")
    live_parser.add_argument("--log", default="alerts.log", help="Alert log output path")
    live_parser.add_argument(
        "--local-ip",
        action="append",
        default=[],
        help="Local IP to use for inbound/outbound live features; repeat for multiple IPs",
    )
    live_parser.set_defaults(func=cmd_live)

    replay_parser = subparsers.add_parser("replay", help="Replay feature CSV through the detector")
    replay_parser.add_argument("--input", required=True, help="Feature CSV to replay")
    replay_parser.add_argument("--model", default="ids_model.pkl", help="Path to trained model")
    replay_parser.add_argument("--scaler", default="scaler.pkl", help="Path to trained scaler")
    replay_parser.add_argument("--threshold", type=float, default=-0.10, help="Alert threshold")
    replay_parser.add_argument("--log", default="alerts.log", help="Alert log output path")
    replay_parser.set_defaults(func=cmd_replay)

    evaluate_parser = subparsers.add_parser("evaluate", help="Evaluate labeled feature CSV")
    evaluate_parser.add_argument("--input", required=True, help="Labeled feature CSV")
    evaluate_parser.add_argument("--model", default="ids_model.pkl", help="Path to trained model")
    evaluate_parser.add_argument("--scaler", default="scaler.pkl", help="Path to trained scaler")
    evaluate_parser.add_argument("--threshold", type=float, default=-0.10, help="Primary alert threshold")
    evaluate_parser.add_argument("--label-column", default="label", help="Ground-truth label column")
    evaluate_parser.add_argument(
        "--sweep",
        type=float,
        nargs="*",
        default=[],
        help="Optional extra thresholds to score in one run",
    )
    evaluate_parser.add_argument("--metrics-out", help="Optional metrics CSV output path")
    evaluate_parser.add_argument("--scored-out", help="Optional per-row score CSV output path")
    evaluate_parser.set_defaults(func=cmd_evaluate)

    label_parser = subparsers.add_parser("label", help="Label a feature CSV for evaluation")
    label_parser.add_argument("--input", required=True, help="Feature CSV to label")
    label_parser.add_argument("--output", required=True, help="Output labeled CSV")
    label_parser.add_argument("--label", required=True, help="Ground-truth label, for example normal or attack")
    label_parser.add_argument("--scenario", required=True, help="Scenario tag, for example nmap_scan")
    label_parser.add_argument("--label-column", default="label", help="Label column name")
    label_parser.add_argument("--scenario-column", default="scenario", help="Scenario column name")
    label_parser.set_defaults(func=cmd_label_dataset)

    merge_parser = subparsers.add_parser("merge", help="Merge labeled feature CSVs")
    merge_parser.add_argument("--inputs", nargs="+", required=True, help="Input labeled CSV files")
    merge_parser.add_argument("--output", required=True, help="Merged dataset output path")
    merge_parser.add_argument("--deduplicate", action="store_true", help="Drop duplicate rows after merge")
    merge_parser.set_defaults(func=cmd_merge_datasets)

    summary_parser = subparsers.add_parser("summary", help="Summarize a labeled dataset")
    summary_parser.add_argument("--input", required=True, help="Merged labeled dataset CSV")
    summary_parser.set_defaults(func=cmd_dataset_summary)

    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n[run_ids] Stopped.")
