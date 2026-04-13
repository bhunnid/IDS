"""
run_ids.py — One-command orchestrator for the full IDS pipeline.
Runs capture + detection together in a single terminal.

Usage:
    python run_ids.py
    python run_ids.py --model ids_model.pkl --iface "Wi-Fi" --threshold -0.10
"""

import argparse
from detect import load_artifacts, run_live

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the full IDS pipeline")
    parser.add_argument("--model",     default="ids_model.pkl", help="Trained model path")
    parser.add_argument("--scaler",    default="scaler.pkl",    help="Trained scaler path")
    parser.add_argument("--iface",     help="Network interface (optional)")
    parser.add_argument("--threshold", type=float, default=-0.10,
                        help="Anomaly score threshold (default: -0.10)")
    args = parser.parse_args()

    model, scaler = load_artifacts(args.model, args.scaler)
    print(f"[IDS] Alert log → alerts.log\n")
    try:
        run_live(model, scaler, args.threshold, iface=args.iface)
    except KeyboardInterrupt:
        print("\n[IDS] Shutdown complete.")
