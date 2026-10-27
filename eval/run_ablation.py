"""
Phase B — Aggregator Ablation Runner (PDF §6.3)
================================================

Runs the evaluation harness over the same dataset under all four aggregation modes
and produces a comparison table showing how Noisy-OR compares to mean, max, and
weighted_mean.

Usage
-----
    cd backend
    python ../eval/run_ablation.py --data ../eval/data/sample_urls.csv

Output
------
    eval/results/ablation_<timestamp>.json
    Printed comparison table
"""

from __future__ import annotations

import asyncio
import csv
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

MODES = ["noisy_or", "mean", "max", "weighted_mean"]
BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
EVAL_SCRIPT = Path(__file__).resolve().parent / "run_eval.py"


def _run_mode(data: str, artifact_type: str, threshold: float, mode: str) -> dict:
    """Run eval harness for one mode as a subprocess and return parsed results."""
    out_path = Path(__file__).parent / "results" / f"ablation_{mode}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, str(EVAL_SCRIPT),
        "--data", data,
        "--type", artifact_type,
        "--threshold", str(threshold),
        "--mode", mode,
        "--out", str(out_path),
        "--n-boot", "500",
    ]

    print(f"  Running mode: {mode}... ", end="", flush=True)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(BACKEND_DIR),
    )

    if result.returncode != 0:
        print(f"FAILED\n{result.stderr[-500:]}")
        return {"mode": mode, "error": result.stderr[-200:]}

    with open(out_path, encoding="utf-8") as f:
        data_obj = json.load(f)

    m = data_obj.get("metrics", {})
    print(
        f"done  →  F1={m.get('f1', '?'):.4f}  "
        f"AUC={m.get('roc_auc', '?'):.4f}  "
        f"Recall={m.get('recall', '?'):.4f}"
    )
    return {"mode": mode, "metrics": m, "confusion": data_obj.get("confusion_matrix", {})}


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Phase B Aggregator Ablation")
    parser.add_argument("--data",      required=True)
    parser.add_argument("--type",      default="url")
    parser.add_argument("--threshold", type=float, default=50.0)
    args = parser.parse_args()

    print(f"\nPhase B — Aggregator Ablation")
    print(f"Dataset: {args.data}  |  Type: {args.type}  |  Threshold: {args.threshold}")
    print("-" * 70)

    results = []
    for mode in MODES:
        res = _run_mode(args.data, args.type, args.threshold, mode)
        results.append(res)

    # Print comparison table
    print("\n" + "=" * 70)
    print(f"{'Mode':<16} {'Precision':>10} {'Recall':>8} {'F1':>8} {'ROC-AUC':>10} {'PR-AUC':>8} {'Brier':>8}")
    print("-" * 70)
    for r in results:
        if "error" in r:
            print(f"{r['mode']:<16} ERROR")
            continue
        m = r["metrics"]
        print(
            f"{r['mode']:<16} "
            f"{m.get('precision', 0):.4f}     "
            f"{m.get('recall', 0):.4f}   "
            f"{m.get('f1', 0):.4f}   "
            f"{m.get('roc_auc', 0):.4f}     "
            f"{m.get('pr_auc', 0):.4f}   "
            f"{m.get('brier_score', 0):.4f}"
        )
    print("=" * 70)
    print("* Hard floors (intel=0.80, CRITICAL=0.70) are preserved in ALL modes.")

    # Save combined report
    out = Path(__file__).parent / "results" / f"ablation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"ablation": results}, f, indent=2)
    print(f"\nFull ablation report saved to: {out}")


if __name__ == "__main__":
    main()
