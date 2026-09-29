# URL Model Card — THREAT-SENSE AI

## Version
`20260929_142658` | Mode: `synthetic_ci`

## Overview
XGBoost classifier (CalibratedClassifierCV with Platt scaling) trained on URL structural features.

> **⚠️ WARNING — SYNTHETIC CI MODEL**
> This model was trained on 100 synthetic/fixture URLs only.
> It is intended for CI testing ONLY and has no meaningful generalization.
> **Run `make train-url-model` with real data before production use.**


## Training Data

| Source | Count | Label |
|---|---|---|
| PhiUSIIL (UCI) | ~100,945 | Phishing (1) |
| Tranco Top-1M | ~134,850 | Benign (0) |
| URLhaus | optional | Malicious (1) |

Domain-aware split: same registered domain never appears in train + test.
Train: 80 | Test: 21
Train positive ratio: 0.500

## Features (28 total)

URL structural features only (no page fetching required).
See `app/engines/url/features.py` for full definitions.

Top features (from rule-weight proxy):
- is_ip_host, has_at_sign, tld_risk, has_punycode, suspicious_token_count

## Metrics (Test Set)

| Metric | Value |
|---|---|
| ROC-AUC | 0.9909 |
| PR-AUC | 0.9924 |
| F1 (macro) | 0.9045 |
| Precision (malicious) | 1.0000 |
| Recall (malicious) | 0.8182 |

Confusion matrix: `[[10, 0], [2, 9]]`

## Latency

| Metric | Value |
|---|---|
| Median inference | 11.63ms |
| P99 inference | 142.88ms |
| Benchmark samples | 100 |

Acceptance criterion: < 50ms offline.  **Status: ❌ FAIL**

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

Trained: 2026-09-29T14:26:58.919769+00:00
