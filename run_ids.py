"""
run_ids.py — Single entry point for the full IDS pipeline.

Modes:
  live     Start live packet capture + real-time detection (default)
  train    Capture normal traffic to CSV, extract features, train model
  replay   Replay a pre-recorded features CSV through the detector

Quick start:
  # Step 1 — capture normal traffic for training (Ctrl+C when done)
  python run_ids.py train --save normal.csv

  # Step 2 — train the model
  python run_ids.py train --features normal_features.csv

  # Step 3 — start live detection
  python run_ids.py live

Full usage:
  python run_ids.py live    [--model PKL] [--scaler PKL] [--iface NAME] [--threshold FLOAT]
  python run_ids.py replay  --features CSV [--model PKL] [--scaler PKL] [--threshold FLOAT]
  python run_ids.py capture --save CSV [--iface NAME]
  python run_ids.py train   --input CSV [--model PKL] [--scaler PKL] [--contamination FLOAT]
"""

import argparse
import sys


def cmd_capture(args):
    """Capture live packets to a CSV file (for training data collection)."""
    from capture import start_capture
    print("[run_ids] Capturing packets — press Ctrl+C when you have enough normal traffic.\n")
    try:
        start_capture(iface=args.iface, save_path=args.save, verbose=args.verbose)
    except KeyboardInterrupt:
        print("\n[run_ids] Capture stopped.")


def cmd_features(args):
    """Extract feature windows from a packet CSV."""
    from features import windowed_features_from_csv
    print(f"[run_ids] Extracting features from {args.input} → {args.output}")
    df = windowed_features_from_csv(args.input, window_sec=args.window)
    df.to_csv(args.output, index=False)
    print(f"[run_ids] {len(df)} windows saved to {args.output}")


def cmd_train(args):
    """Train the Isolation Forest on a features CSV."""
    from train import train
    train(
        features_csv  = args.input,
        model_path    = args.model,
        scaler_path   = args.scaler,
        contamination = args.contamination,
    )


def cmd_live(args):
    """Start live detection (capture + inference)."""
    from detect import load_artifacts, run_live
    model, scaler = load_artifacts(args.model, args.scaler)
    print("[run_ids] Starting live IDS — press Ctrl+C to stop.\n")
    try:
        run_live(model, scaler, threshold=args.threshold, iface=args.iface)
    except KeyboardInterrupt:
        print("\n[run_ids] Stopped cleanly.")


def cmd_replay(args):
    """Replay a features CSV through the detector (offline testing)."""
    from detect import load_artifacts, run_replay
    model, scaler = load_artifacts(args.model, args.scaler)
    run_replay(model, scaler, features_csv=args.features, threshold=args.threshold)


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_ids.py",
        description="Lightweight Anomaly-Based IDS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── capture ──────────────────────────────────────────────────────────────
    p_cap = sub.add_parser("capture", help="Capture packets to CSV")
    p_cap.add_argument("--save",    required=True,  metavar="CSV",
                       help="Output CSV path")
    p_cap.add_argument("--iface",   default=None,   metavar="NAME",
                       help="Network interface name")
    p_cap.add_argument("--verbose", action="store_true", default=True,
                       help="Print each packet (default: on)")

    # ── features ─────────────────────────────────────────────────────────────
    p_feat = sub.add_parser("features", help="Extract features from packet CSV")
    p_feat.add_argument("--input",  required=True, metavar="CSV",
                        help="Packet CSV from 'capture'")
    p_feat.add_argument("--output", required=True, metavar="CSV",
                        help="Output features CSV")
    p_feat.add_argument("--window", default=10,    type=int, metavar="SEC",
                        help="Window size in seconds (default: 10)")

    # ── train ─────────────────────────────────────────────────────────────────
    p_train = sub.add_parser("train", help="Train IsolationForest on features CSV")
    p_train.add_argument("--input",         required=True,        metavar="CSV",
                         help="Features CSV")
    p_train.add_argument("--model",         default="ids_model.pkl", metavar="PKL",
                         help="Output model path")
    p_train.add_argument("--scaler",        default="scaler.pkl", metavar="PKL",
                         help="Output scaler path")
    p_train.add_argument("--contamination", default=0.05,         type=float,
                         metavar="FLOAT",   help="Contamination rate (default: 0.05)")

    # ── live ──────────────────────────────────────────────────────────────────
    p_live = sub.add_parser("live", help="Start live capture + detection")
    p_live.add_argument("--model",     default="ids_model.pkl", metavar="PKL")
    p_live.add_argument("--scaler",    default="scaler.pkl",    metavar="PKL")
    p_live.add_argument("--iface",     default=None,            metavar="NAME")
    p_live.add_argument("--threshold", default=-0.10,           type=float,
                        metavar="FLOAT", help="Anomaly score threshold (default: -0.10)")

    # ── replay ────────────────────────────────────────────────────────────────
    p_replay = sub.add_parser("replay", help="Replay features CSV (offline test)")
    p_replay.add_argument("--features",  required=True,           metavar="CSV")
    p_replay.add_argument("--model",     default="ids_model.pkl", metavar="PKL")
    p_replay.add_argument("--scaler",    default="scaler.pkl",    metavar="PKL")
    p_replay.add_argument("--threshold", default=-0.10,           type=float,
                          metavar="FLOAT")

    return parser


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = build_parser()
    args   = parser.parse_args()

    dispatch = {
        "capture":  cmd_capture,
        "features": cmd_features,
        "train":    cmd_train,
        "live":     cmd_live,
        "replay":   cmd_replay,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    handler(args)
