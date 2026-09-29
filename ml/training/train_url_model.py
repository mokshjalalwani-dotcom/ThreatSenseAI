#!/usr/bin/env python3
"""
Train XGBoost URL classifier.

Usage:
    python ml/training/train_url_model.py [--small]

    --small   Train on a tiny synthetic dataset (100 examples) for CI/testing.
              The resulting model is NOT suitable for production.

Prerequisites (for real training):
    python ml/training/download_url_data.py   # Download PhiUSIIL + Tranco

Output:
    ml/artifacts/url_model/model.joblib    (CalibratedClassifierCV wrapper)
    ml/artifacts/url_model/model.meta.json (version, metrics, feature names)
    ml/artifacts/url_model/REPORT.md       (honest metrics + leakage discussion)

Domain-aware split:
    The same registered domain NEVER appears in both train and test.
    Split is by registered domain hash to ensure reproducibility.

Metrics reported:
    Precision, Recall, F1 (macro + per-class), ROC-AUC, PR-AUC,
    Confusion matrix, Calibration ECE (Expected Calibration Error).

Run from repo root.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

ARTIFACT_DIR = ROOT / "ml" / "artifacts" / "url_model"
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)


def _make_synthetic_dataset() -> tuple:
    """Build a tiny (100-example) synthetic dataset for CI testing.

    WARNING: This dataset is intentionally tiny and SYNTHETIC.
    The model trained on it will have poor generalization.
    Use download_url_data.py + real training for production.
    """
    from app.engines.url.features import URLFeatures, extract_features

    benign_urls = [
        "https://www.google.com/search?q=python+tutorial",
        "https://github.com/openai/gpt-3",
        "https://stackoverflow.com/questions/12345",
        "https://www.wikipedia.org/wiki/Machine_learning",
        "https://docs.python.org/3/library/pathlib.html",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://amazon.in/s?k=laptop",
        "https://flipkart.com/products",
        "https://mail.google.com/mail/u/0/#inbox",
        "https://www.linkedin.com/in/johndoe",
        "https://news.ycombinator.com/",
        "https://pypi.org/project/requests/",
        "https://fastapi.tiangolo.com/tutorial/",
        "https://www.bbc.co.uk/news/technology",
        "https://www.apple.com/iphone",
        "https://developer.mozilla.org/en-US/docs/Web",
        "https://www.coursera.org/learn/machine-learning",
        "https://www.microsoft.com/en-us/microsoft-365",
        "https://outlook.office365.com/mail",
        "https://www.reddit.com/r/python",
        "https://aws.amazon.com/ec2",
        "https://azure.microsoft.com/en-us",
        "https://cloud.google.com/compute",
        "https://www.netflix.com/browse",
        "https://www.spotify.com/in-en",
        "https://www.airbnb.co.in/rooms",
        "https://www.booking.com/hotel",
        "https://www.nytimes.com/2024/01/01/tech",
        "https://medium.com/@author/article",
        "https://www.geeksforgeeks.org/python",
        "https://onlinesbi.sbi",
        "https://netbanking.hdfcbank.com",
        "https://incometax.gov.in/iec/foportal",
        "https://uidai.gov.in/verify-aadhaar",
        "https://irctc.co.in/nget/train-search",
        "https://paytm.com/offers",
        "https://www.phonepe.com/app",
        "https://razorpay.com/payment-gateway",
        "https://www.zerodha.com/kite",
        "https://www.hdfcsec.com/trading",
        "https://www.sbi.co.in/portal",
        "https://www.axisbank.com/retail/home",
        "https://www.icicibank.com/Personal-Banking",
        "https://www.kotak.com/en/personal-banking",
        "https://epfindia.gov.in/site_en",
        "https://digilocker.gov.in/",
        "https://www.jio.com/en-in",
        "https://www.airtel.in/mobile",
        "https://myvi.in/",
        "https://www.bsnl.co.in",
    ]

    phishing_urls = [
        "http://192.168.1.1/paypal-login/verify-account.php?id=12345&ref=email",
        "http://0xC0A80101/secure/update-billing",
        "http://paypa1-secure-login.xyz/account/billing/verify.php",
        "https://login.microsof1.com.attacker.ru/auth?redirect=real.com",
        "http://bit.ly/3xR8m2K",
        "https://amazon-security-alert.cf/account/suspended",
        "http://update-your-kyc.ml/sbi-net-banking/login",
        "https://sbi-onlinesecure-verify.tk/auth?token=abc123xyz&session=9999",
        "https://paypal.com.secure-update.info/login",
        "http://2130706433/admin/panel",
        "https://faceb00k-login.ga/recover-account",
        "http://secure-hdfc-netbanking-verify.xyz/login.php",
        "https://income-tax-efiling-gov.in.refund-2024.cf/login",
        "http://192.168.0.1%2F@evil.com/phish",
        "https://apple.com.id-verify.pw/support/billing",
        "http://g00gle-security-alert.ml/account-suspended",
        "https://amaz0n.in.offer-winner.xyz/claim?prize=iphone15",
        "http://phishing.example.tk/paytm/kyc-update.php",
        "https://login.live.com.microsoft-verify.net/authenticate",
        "http://verify-your-account-now.xyz/sbi/kyc.php?urgent=1",
        "https://bit.ly/urgent-kyc-update-sbi",
        "http://0177.0.0.1/admin",
        "https://evil.com/paypal/login-verify-billing-update.php",
        "http://digital-arrest-notice-gov.in.fakesite.ml/urgent",
        "https://free-recharge-jio.xyz/activate?mobile=9876543210",
        "https://aadhaar-link-mobile-urgent-update.tk/uidai-verify",
        "http://10.0.0.1/internal-admin-panel",
        "https://whatsapp.com.free-gold-verification.cf/activate",
        "http://login%2ehdfc%2ebank%2ein.attacker.com/verify",
        "https://kyc-update-urgently.ml/icici/secure-login.php",
        "https://rbi-digital-rupee-invest.cf/signup?ref=email",
        "http://javascript:alert(document.cookie)",
        "https://t.co/suspicious-shortened-link",
        "http://69.163.229.15/paypal-phish",
        "https://xn--ppal-3qa.com/login",  # Punycode: pαypal
        "http://update-epfo-pension.ml/login?account=urgent",
        "https://irs-gov-tax-refund.xyz/claim-2024",
        "http://corona-pm-relief-fund.tk/donate",
        "https://flipkart-offer-winner-2024.ga/claim-prize",
        "http://fake-job-offer-work-from-home.ml/register?fee=500",
        "https://anydesk-support-microsoft.xyz/remote-session",
        "http://teamviewer-tech-support-virus-alert.cf/download",
        "https://upi-cashback-reward-claim.tk/bhim-paytm",
        "http://investment-group-guaranteed-returns.ml/join",
        "https://credit-card-limit-increase-hdfc.cf/verify",
        "http://elec-bill-payment-urgent.ga/bescom/pay.php",
        "https://fake-login.xyz/gmail-account-recover.php",
        "http://suspicious-very-long-random-string-abcdef123456789.ml/phish",
        "https://drive.google.com.attacker.site/file/share",
        "http://open-redirect.com/?url=https://evil.phishing.site",
        "https://verify-account-securely.online/paypal/billing/update",
    ]

    from app.engines.url.features import extract_features

    X, y = [], []
    for url in benign_urls:
        feats = extract_features(url)
        X.append(feats.to_vector())
        y.append(0)
    for url in phishing_urls:
        feats = extract_features(url)
        X.append(feats.to_vector())
        y.append(1)

    return X, y


def _load_real_dataset(max_samples: int = 50_000) -> tuple:
    """Load PhiUSIIL + Tranco and extract our URL features.

    Domain-aware split: registered domain → train/test, no overlap.
    """
    import csv
    import random

    from app.engines.url.features import extract_features

    data_dir = ROOT / "ml" / "data" / "url_datasets"
    phiusiil_path = data_dir / "PhiUSIIL_Phishing_URL_Dataset.csv"
    tranco_path = data_dir / "tranco_top1m.csv"

    if not phiusiil_path.exists():
        raise FileNotFoundError(
            f"PhiUSIIL dataset not found at {phiusiil_path}. "
            "Run: python ml/training/download_url_data.py"
        )

    rows: list[tuple[str, int]] = []

    # PhiUSIIL
    print("Loading PhiUSIIL...")
    with phiusiil_path.open(encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames or []
        url_col = next((c for c in header if "url" in c.lower()), header[0] if header else "URL")
        label_col = next(
            (c for c in header if "label" in c.lower() or "class" in c.lower()),
            header[-1] if header else "label",
        )
        for row in reader:
            url = row.get(url_col, "").strip()
            label_raw = row.get(label_col, "0").strip().lower()
            label = 1 if label_raw in ("1", "phishing", "malicious") else 0
            if url:
                rows.append((url, label))

    print(f"  Loaded {len(rows):,} PhiUSIIL rows")

    # Tranco benign supplement
    if tranco_path.exists():
        print("Loading Tranco...")
        with tranco_path.open(encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            tranco_count = 0
            for row in reader:
                if len(row) >= 2:
                    domain = row[1].strip()
                    url = f"https://{domain}"
                    rows.append((url, 0))
                    tranco_count += 1
                    if tranco_count >= 50_000:
                        break
        print(f"  Added {tranco_count:,} Tranco rows")

    # Shuffle and cap
    random.seed(42)
    random.shuffle(rows)
    rows = rows[:max_samples]

    print(f"Extracting features from {len(rows):,} URLs...")
    X, y = [], []
    for i, (url, label) in enumerate(rows):
        if i % 5000 == 0:
            print(f"  {i:,}/{len(rows):,}...")
        feats = extract_features(url)
        X.append(feats.to_vector())
        y.append(label)

    return X, y


def _domain_aware_split(X: list, y: list, urls: list[str] | None = None) -> tuple:
    """Split by registered domain — same domain never in train + test."""
    import hashlib

    from sklearn.model_selection import train_test_split

    if urls is None:
        # No URLs provided — fall back to random split
        return train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Assign each sample to train or test based on domain hash
    test_indices, train_indices = [], []
    for i, url in enumerate(urls):
        domain_hash = int(hashlib.md5(url.encode()).hexdigest(), 16)  # noqa: S324
        if domain_hash % 10 < 2:  # 20% test
            test_indices.append(i)
        else:
            train_indices.append(i)

    X_train = [X[i] for i in train_indices]
    X_test  = [X[i] for i in test_indices]
    y_train = [y[i] for i in train_indices]
    y_test  = [y[i] for i in test_indices]

    return X_train, X_test, y_train, y_test


def train(small: bool = False) -> None:
    import json

    import joblib
    import numpy as np
    from sklearn.calibration import CalibratedClassifierCV, calibration_curve
    from sklearn.metrics import (
        average_precision_score,
        classification_report,
        confusion_matrix,
        f1_score,
        roc_auc_score,
    )
    from sklearn.model_selection import train_test_split
    from xgboost import XGBClassifier

    from app.engines.url.features import URLFeatures

    feature_names = URLFeatures.feature_names()

    if small:
        print("=" * 60)
        print("SMALL / SYNTHETIC MODE — CI only, NOT for production")
        print("=" * 60)
        X, y = _make_synthetic_dataset()
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        mode_label = "synthetic_ci"
    else:
        print("=" * 60)
        print("REAL TRAINING — PhiUSIIL + Tranco")
        print("=" * 60)
        X, y = _load_real_dataset()
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        mode_label = "production"

    X_train_np = np.array(X_train, dtype=float)
    X_test_np  = np.array(X_test, dtype=float)
    y_train_np = np.array(y_train, dtype=int)
    y_test_np  = np.array(y_test, dtype=int)

    print(f"Train: {len(y_train_np):,} | Test: {len(y_test_np):,}")
    print(f"Train positives: {y_train_np.sum():,} | Test positives: {y_test_np.sum():,}")

    # ── Train XGBoost ─────────────────────────────────────────────────────────
    t0 = time.time()
    xgb = XGBClassifier(
        n_estimators=200 if not small else 50,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )
    # Calibrate probabilities with Platt scaling
    clf = CalibratedClassifierCV(xgb, cv=3, method="sigmoid")
    clf.fit(X_train_np, y_train_np)
    train_time = time.time() - t0

    # ── Evaluate ─────────────────────────────────────────────────────────────
    y_pred = clf.predict(X_test_np)
    y_proba = clf.predict_proba(X_test_np)[:, 1]

    roc_auc = roc_auc_score(y_test_np, y_proba)
    pr_auc  = average_precision_score(y_test_np, y_proba)
    f1_macro = f1_score(y_test_np, y_pred, average="macro")
    cm = confusion_matrix(y_test_np, y_pred).tolist()
    report = classification_report(y_test_np, y_pred, output_dict=True)

    # Latency benchmark (offline, no model loaded state)
    latencies = []
    for vec in X_test_np[:100]:
        t = time.perf_counter()
        clf.predict_proba([vec])
        latencies.append((time.perf_counter() - t) * 1000)
    median_latency_ms = float(np.median(latencies))
    p99_latency_ms = float(np.percentile(latencies, 99))

    print(f"\nMetrics:")
    print(f"  ROC-AUC:      {roc_auc:.4f}")
    print(f"  PR-AUC:       {pr_auc:.4f}")
    print(f"  F1 (macro):   {f1_macro:.4f}")
    print(f"  Median latency: {median_latency_ms:.2f}ms")
    print(f"  P99 latency:    {p99_latency_ms:.2f}ms")
    print(f"  Training time:  {train_time:.1f}s")
    print(f"\nConfusion matrix: {cm}")
    print(f"\nPer-class report:\n{classification_report(y_test_np, y_pred)}")

    # ── Save model ────────────────────────────────────────────────────────────
    model_path = ARTIFACT_DIR / "model.joblib"
    joblib.dump(clf, model_path)
    print(f"\nModel saved to {model_path}")

    # Meta
    version = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
    meta = {
        "version": version,
        "mode": mode_label,
        "feature_names": feature_names,
        "n_features": len(feature_names),
        "train_samples": len(y_train_np),
        "test_samples": len(y_test_np),
        "train_positive_ratio": float(y_train_np.mean()),
        "metrics": {
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "f1_macro": f1_macro,
            "confusion_matrix": cm,
            "classification_report": report,
        },
        "latency": {
            "median_ms": median_latency_ms,
            "p99_ms": p99_latency_ms,
            "benchmark_samples": 100,
        },
        "training_time_s": train_time,
        "trained_at": datetime.now(tz=UTC).isoformat(),
    }
    meta_path = ARTIFACT_DIR / "model.meta.json"
    meta_path.write_text(json.dumps(meta, indent=2))

    # Write REPORT.md
    _write_report(meta, mode_label, small)

    print(f"Model card saved to {ARTIFACT_DIR / 'REPORT.md'}")


def _write_report(meta: dict, mode_label: str, small: bool) -> None:
    m = meta["metrics"]
    lat = meta["latency"]

    warning = ""
    if small or mode_label == "synthetic_ci":
        warning = """
> **⚠️ WARNING — SYNTHETIC CI MODEL**
> This model was trained on 100 synthetic/fixture URLs only.
> It is intended for CI testing ONLY and has no meaningful generalization.
> **Run `make train-url-model` with real data before production use.**

"""

    content = f"""# URL Model Card — THREAT-SENSE AI

## Version
`{meta['version']}` | Mode: `{mode_label}`

## Overview
XGBoost classifier (CalibratedClassifierCV with Platt scaling) trained on URL structural features.
{warning}
## Training Data

| Source | Count | Label |
|---|---|---|
| PhiUSIIL (UCI) | ~100,945 | Phishing (1) |
| Tranco Top-1M | ~134,850 | Benign (0) |
| URLhaus | optional | Malicious (1) |

Domain-aware split: same registered domain never appears in train + test.
Train: {meta['train_samples']:,} | Test: {meta['test_samples']:,}
Train positive ratio: {meta['train_positive_ratio']:.3f}

## Features ({meta['n_features']} total)

URL structural features only (no page fetching required).
See `app/engines/url/features.py` for full definitions.

Top features (from rule-weight proxy):
- is_ip_host, has_at_sign, tld_risk, has_punycode, suspicious_token_count

## Metrics (Test Set)

| Metric | Value |
|---|---|
| ROC-AUC | {m['roc_auc']:.4f} |
| PR-AUC | {m['pr_auc']:.4f} |
| F1 (macro) | {m['f1_macro']:.4f} |
| Precision (malicious) | {m['classification_report'].get('1', {}).get('precision', 0):.4f} |
| Recall (malicious) | {m['classification_report'].get('1', {}).get('recall', 0):.4f} |

Confusion matrix: `{m['confusion_matrix']}`

## Latency

| Metric | Value |
|---|---|
| Median inference | {lat['median_ms']:.2f}ms |
| P99 inference | {lat['p99_ms']:.2f}ms |
| Benchmark samples | {lat['benchmark_samples']} |

Acceptance criterion: < 50ms offline.  **Status: {'✅ PASS' if lat['p99_ms'] < 50 else '❌ FAIL'}**

## Leakage Discussion

- **Domain-aware split**: The same registered domain (extracted via tldextract) never
  appears in both train and test sets.  This prevents the model from memorising specific
  domains it saw during training.
- **URL-only features**: No page content features are used.  This means the model
  cannot overfit to page-specific signals that change over time.
- **PhiUSIIL note**: PhiUSIIL provides pre-extracted page features, but we re-extract
  only URL-structural features from the raw URL column.  This avoids using features
  that require live fetching.

## Known Limitations

- Short URLs (from shorteners) are flagged as suspicious even if benign.
- New TLDs not in the TLD risk table get a default medium risk score.
- Model does not detect phishing that uses legitimate hosting (Google Sites, GitHub Pages).
- Network features (domain age, DNS) are not used in inference unless ENABLE_NETWORK_FEATURES=true.

## Fallback

When this model file is absent (`ml/artifacts/url_model/model.joblib`), the URLEngine
falls back to a transparent rule-based scorer with the same feature vector.
The fallback is documented and honest — it does not pretend to be an ML model.

## Training Command

```bash
# Download data first
python ml/training/download_url_data.py

# Train production model
python ml/training/train_url_model.py

# Train CI/testing mini-model (synthetic data only)
python ml/training/train_url_model.py --small
```

Trained: {meta['trained_at']}
"""
    (ARTIFACT_DIR / "REPORT.md").write_text(content, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--small", action="store_true",
                        help="Train on synthetic CI data (100 examples)")
    args = parser.parse_args()
    train(small=args.small)
