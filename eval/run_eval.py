"""
ThreatSense AI — Phase A Evaluation Harness (PDF §6.3, §6.6)
=============================================================

Runs the full internal analysis pipeline over a labelled CSV and reports:
  - Precision, Recall, F1
  - ROC-AUC, PR-AUC
  - Recall at 1% and 5% false-positive rate
  - Brier score
  - Expected Calibration Error (ECE)
  - Bootstrap 95% confidence intervals

Usage
-----
    # From repo root
    cd backend
    python ../eval/run_eval.py --data ../eval/data/sample_urls.csv \\
                               --label-col label --content-col url \\
                               --type url --threshold 50 \\
                               --mode noisy_or

CSV format
----------
    url,label
    http://secure-paypal-login.xyz,1
    https://www.google.com,0
    ...

label=1 means malicious/phishing; label=0 means benign.

Options
-------
    --mode      noisy_or | mean | max | weighted_mean  (default: noisy_or)
    --threshold 0-100 score above which verdict is flagged as malicious (default: 50)
    --n-boot    number of bootstrap resamples for CI (default: 1000)
    --out       path to save JSON results (default: eval/results/report_<timestamp>.json)
    --type      artifact type sent to analyze: url | sms | email | webpage (default: url)
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Allow running from repo root without installing the package ────────────────
BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import numpy as np  # type: ignore[import]

logging.basicConfig(level=logging.WARNING)

# ── Metrics ────────────────────────────────────────────────────────────────────

def _brier(probs: list[float], labels: list[int]) -> float:
    return float(np.mean([(p - y) ** 2 for p, y in zip(probs, labels)]))


def _ece(probs: list[float], labels: list[int], n_bins: int = 10) -> float:
    """Expected Calibration Error — equal-width bins."""
    bins = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        lo, hi = bins[i], bins[i + 1]
        mask = [(lo <= p < hi) for p in probs]
        if not any(mask):
            continue
        bin_probs = [p for p, m in zip(probs, mask) if m]
        bin_labs  = [y for y, m in zip(labels, mask) if m]
        ece += len(bin_probs) * abs(np.mean(bin_probs) - np.mean(bin_labs))
    return float(ece / len(probs))


def _roc_auc(probs: list[float], labels: list[int]) -> float:
    from sklearn.metrics import roc_auc_score  # type: ignore[import]
    return float(roc_auc_score(labels, probs))


def _pr_auc(probs: list[float], labels: list[int]) -> float:
    from sklearn.metrics import average_precision_score  # type: ignore[import]
    return float(average_precision_score(labels, probs))


def _recall_at_fpr(probs: list[float], labels: list[int], target_fpr: float) -> float:
    """Recall at a fixed false-positive rate threshold."""
    from sklearn.metrics import roc_curve  # type: ignore[import]
    fprs, tprs, _ = roc_curve(labels, probs)
    # Find first threshold where FPR <= target
    for fpr, tpr in zip(fprs, tprs):
        if fpr >= target_fpr:
            return float(tpr)
    return float(tprs[-1])


def _prf(preds: list[int], labels: list[int]) -> dict[str, float]:
    tp = sum(p == 1 and y == 1 for p, y in zip(preds, labels))
    fp = sum(p == 1 and y == 0 for p, y in zip(preds, labels))
    fn = sum(p == 0 and y == 1 for p, y in zip(preds, labels))
    tn = sum(p == 0 and y == 0 for p, y in zip(preds, labels))
    prec  = tp / (tp + fp) if (tp + fp) else 0.0
    rec   = tp / (tp + fn) if (tp + fn) else 0.0
    f1    = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc   = (tp + tn) / len(labels) if labels else 0.0
    return {"precision": prec, "recall": rec, "f1": f1, "accuracy": acc, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def _bootstrap_ci(
    fn,
    probs: list[float],
    labels: list[int],
    n: int = 1000,
    alpha: float = 0.05,
) -> tuple[float, float]:
    rng = np.random.default_rng(42)
    stats = []
    arr_p = np.array(probs)
    arr_l = np.array(labels)
    for _ in range(n):
        idx = rng.integers(0, len(probs), len(probs))
        try:
            stats.append(fn(arr_p[idx].tolist(), arr_l[idx].tolist()))
        except Exception:
            pass
    if not stats:
        return (float("nan"), float("nan"))
    lo = float(np.percentile(stats, 100 * alpha / 2))
    hi = float(np.percentile(stats, 100 * (1 - alpha / 2)))
    return lo, hi


# ── Pipeline call ──────────────────────────────────────────────────────────────

async def _analyze_one(content: str, artifact_type: str) -> dict:
    """Run the full ThreatSense pipeline on a single artifact and return the report dict."""
    from app.api.routes.analyze import _run_pipeline  # type: ignore[import]
    from app.schemas.schemas import Artifact, ArtifactType  # type: ignore[import]

    atype_map = {
        "url": ArtifactType.URL,
        "sms": ArtifactType.SMS,
        "email": ArtifactType.EMAIL,
        "webpage": ArtifactType.WEBPAGE,
    }
    atype = atype_map.get(artifact_type.lower(), ArtifactType.URL)
    artifact = Artifact(type=atype, raw_content=content)
    report = await _run_pipeline(artifact)
    return report.model_dump()


async def _run_dataset(
    rows: list[dict],
    artifact_type: str,
    verbose: bool = False,
) -> list[dict]:
    results = []
    for i, row in enumerate(rows):
        content = row["content"]
        label   = int(row["label"])
        t0 = time.perf_counter()
        try:
            rep = await _analyze_one(content, artifact_type)
            score = rep.get("risk_score", 0.0) or 0.0
            verdict = rep.get("verdict", "unknown")
            latency = time.perf_counter() - t0
            results.append({
                "content": content[:80],
                "label": label,
                "score": score,
                "prob": score / 100.0,
                "verdict": verdict,
                "latency_s": round(latency, 3),
                "error": None,
            })
            if verbose:
                print(f"  [{i+1}/{len(rows)}] score={score:.1f} verdict={verdict} label={label} ({latency:.2f}s)")
        except Exception as exc:
            results.append({"content": content[:80], "label": label, "score": 0.0, "prob": 0.0,
                            "verdict": "error", "latency_s": 0.0, "error": str(exc)})
            if verbose:
                print(f"  [{i+1}/{len(rows)}] ERROR: {exc}")
    return results


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatSense AI Evaluation Harness (Phase A)")
    parser.add_argument("--data",       required=True,  help="Path to labelled CSV file")
    parser.add_argument("--label-col",  default="label",   help="Column name for binary label (1=malicious)")
    parser.add_argument("--content-col",default="url",     help="Column name for artifact content")
    parser.add_argument("--type",       default="url",     help="Artifact type: url | sms | email | webpage")
    parser.add_argument("--threshold",  type=float, default=50.0, help="Score threshold for binary decision (0-100)")
    parser.add_argument("--mode",       default=None,     help="Override AGGREGATION_MODE: noisy_or|mean|max|weighted_mean")
    parser.add_argument("--n-boot",     type=int, default=1000, help="Bootstrap resamples for CI")
    parser.add_argument("--out",        default=None,     help="Output JSON file path")
    parser.add_argument("--verbose",    action="store_true")
    args = parser.parse_args()

    # Apply aggregation mode override
    if args.mode:
        os.environ["AGGREGATION_MODE"] = args.mode
        # Re-load settings (pydantic-settings reads env at construction)
        from app.core import config as _cfg  # type: ignore[import]
        _cfg.settings = _cfg.Settings()

    # Load CSV
    data_path = Path(args.data)
    if not data_path.exists():
        print(f"ERROR: File not found: {data_path}")
        sys.exit(1)

    rows = []
    with open(data_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({"content": row[args.content_col], "label": row[args.label_col]})

    print(f"\nThreatSense AI — Evaluation Harness")
    print(f"Dataset : {data_path.name} ({len(rows)} samples)")
    print(f"Type    : {args.type}")
    print(f"Mode    : {args.mode or 'noisy_or (default)'}")
    print(f"Thresh  : {args.threshold}\n")

    # Run pipeline
    raw = asyncio.run(_run_dataset(rows, args.type, verbose=args.verbose))

    probs  = [r["prob"] for r in raw]
    labels = [r["label"] for r in raw]
    preds  = [1 if r["score"] >= args.threshold else 0 for r in raw]
    errors = [r for r in raw if r["error"]]

    # Metrics
    prf   = _prf(preds, labels)
    brier = _brier(probs, labels)
    ece   = _ece(probs, labels)
    latencies = [r["latency_s"] for r in raw if not r["error"]]

    try:
        roc_auc_val   = _roc_auc(probs, labels)
        pr_auc_val    = _pr_auc(probs, labels)
        rec_at_1_fpr  = _recall_at_fpr(probs, labels, 0.01)
        rec_at_5_fpr  = _recall_at_fpr(probs, labels, 0.05)
        roc_ci        = _bootstrap_ci(_roc_auc,  probs, labels, args.n_boot)
        pr_ci         = _bootstrap_ci(_pr_auc,   probs, labels, args.n_boot)
        f1_ci         = _bootstrap_ci(
            lambda p, l: _prf([1 if x >= args.threshold / 100.0 else 0 for x in p], l)["f1"],
            probs, labels, args.n_boot,
        )
    except Exception as e:
        print(f"  Warning: AUC metrics unavailable ({e})")
        roc_auc_val = pr_auc_val = rec_at_1_fpr = rec_at_5_fpr = float("nan")
        roc_ci = pr_ci = f1_ci = (float("nan"), float("nan"))

    # Report
    report = {
        "run_at":          datetime.now(timezone.utc).isoformat(),
        "dataset":         str(data_path),
        "n_samples":       len(rows),
        "n_errors":        len(errors),
        "artifact_type":   args.type,
        "aggregation_mode": args.mode or "noisy_or",
        "threshold":       args.threshold,
        "metrics": {
            "precision":       round(prf["precision"], 4),
            "recall":          round(prf["recall"],    4),
            "f1":              round(prf["f1"],        4),
            "f1_ci_95":        [round(f1_ci[0], 4), round(f1_ci[1], 4)],
            "accuracy":        round(prf["accuracy"],  4),
            "roc_auc":         round(roc_auc_val, 4),
            "roc_auc_ci_95":   [round(roc_ci[0], 4), round(roc_ci[1], 4)],
            "pr_auc":          round(pr_auc_val,  4),
            "pr_auc_ci_95":    [round(pr_ci[0],  4), round(pr_ci[1],  4)],
            "recall_at_1pct_fpr": round(rec_at_1_fpr, 4),
            "recall_at_5pct_fpr": round(rec_at_5_fpr, 4),
            "brier_score":     round(brier, 4),
            "ece":             round(ece,   4),
        },
        "confusion_matrix": {"tp": prf["tp"], "fp": prf["fp"], "fn": prf["fn"], "tn": prf["tn"]},
        "latency": {
            "mean_s":   round(float(np.mean(latencies)), 3) if latencies else 0,
            "median_s": round(float(np.median(latencies)), 3) if latencies else 0,
            "p95_s":    round(float(np.percentile(latencies, 95)), 3) if latencies else 0,
        },
        "per_sample": raw,
    }

    # Print summary
    m = report["metrics"]
    cm = report["confusion_matrix"]
    print("=" * 60)
    print(f"  Precision : {m['precision']:.4f}")
    print(f"  Recall    : {m['recall']:.4f}")
    print(f"  F1        : {m['f1']:.4f}  95% CI [{m['f1_ci_95'][0]:.4f}, {m['f1_ci_95'][1]:.4f}]")
    print(f"  Accuracy  : {m['accuracy']:.4f}")
    print(f"  ROC-AUC   : {m['roc_auc']:.4f}  95% CI [{m['roc_auc_ci_95'][0]:.4f}, {m['roc_auc_ci_95'][1]:.4f}]")
    print(f"  PR-AUC    : {m['pr_auc']:.4f}  95% CI [{m['pr_auc_ci_95'][0]:.4f}, {m['pr_auc_ci_95'][1]:.4f}]")
    print(f"  Rec@1%FPR : {m['recall_at_1pct_fpr']:.4f}")
    print(f"  Rec@5%FPR : {m['recall_at_5pct_fpr']:.4f}")
    print(f"  Brier     : {m['brier_score']:.4f}")
    print(f"  ECE       : {m['ece']:.4f}")
    print(f"  Latency   : mean={report['latency']['mean_s']}s  p95={report['latency']['p95_s']}s")
    print(f"  Confusion : TP={cm['tp']} FP={cm['fp']} FN={cm['fn']} TN={cm['tn']}")
    print(f"  Errors    : {report['n_errors']}")
    print("=" * 60)

    # Save
    out_path = Path(args.out) if args.out else (
        Path(__file__).parent / "results" / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\nFull report saved to: {out_path}")


if __name__ == "__main__":
    main()
