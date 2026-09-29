# ML Data — Dataset Sources & Download Instructions

## URL Model Datasets (Stage 3)

### Primary: PhiUSIIL Phishing URL Dataset (UCI ML Repository)

| Field | Value |
|---|---|
| Source | [UCI Machine Learning Repository](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) |
| DOI | https://doi.org/10.24432/C5GW2H |
| Licence | Creative Commons Attribution 4.0 (CC BY 4.0) |
| Size | ~235,795 URLs (134,850 legitimate + 100,945 phishing) |
| Login required? | **No** — direct download |
| Citation | Prasad, A., & Chandra, S. (2023). PhiUSIIL: A diverse security profile empowered phishing URL detection framework. *Computers & Security* |

Download (run from repo root):
```bash
python ml/training/download_url_data.py
```
This places the file at `ml/data/url_datasets/PhiUSIIL_Phishing_URL_Dataset.csv`.

**Important notes:**
- PhiUSIIL provides BOTH raw URLs and pre-extracted features (some page-content-based).
- Our training script re-extracts our own URL-structural features from the raw URL column.
- We do NOT use the page-content features (URLTitleMatchScore, etc.) because they require live fetching.

---

### Benign Supplement: Tranco Top-1M List

| Field | Value |
|---|---|
| Source | [tranco-list.eu](https://tranco-list.eu) |
| Licence | Public data — attribution to Tranco research project |
| Size | 1,000,000 domain names |
| Login required? | **No** — direct download |
| Citation | Le Pochat V. et al. (2019). Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation. NDSS |

Downloaded automatically by `ml/training/download_url_data.py` to `ml/data/url_datasets/tranco_top1m.csv`.

---

### Optional Malicious Supplement: URLhaus

| Field | Value |
|---|---|
| Source | [urlhaus-api.abuse.ch](https://urlhaus-api.abuse.ch/) |
| Licence | CC0 1.0 (for non-commercial use; commercial entities require subscription) |
| Login required? | **Free Auth-Key required** — register at https://urlhaus-api.abuse.ch/ |
| API Key env var | `URLHAUS_AUTH_KEY` in `.env` |

The download script skips URLhaus silently if `URLHAUS_AUTH_KEY` is not set.

---

## Class Balance

After sampling for training (target ~50,000 examples):

| Source | Class | Count |
|---|---|---|
| PhiUSIIL | Phishing | ~50,000 |
| PhiUSIIL + Tranco | Legitimate | ~50,000 |
| URLhaus (optional) | Malicious | up to 30,000 |

Stratified train/validation/test split **by registered domain** to prevent data leakage (the same domain never appears in both train and test).

---

## NLP Datasets (Stages 4, 7, 13)

| Dataset | Stage | Source | Licence | Login |
|---|---|---|---|---|
| SMS Spam Collection | 7, 13 | UCI ML Repository | CC BY 4.0 | No |
| SpamAssassin Public Corpus | 7, 13 | Apache Foundation | Apache 2.0 | No |
| Enron Email Dataset | 7, 13 | CMU / FERC | Public | No |
| EMSCAD (Email Scam) | 13 | Mendeley Data | CC BY 4.0 | No |

Download scripts TBD for each stage.

---

## Gold Labels (Stage 13)

The file `ml/data/gold_labels_template.csv` is the labeling template for human annotation.
The filled file `ml/data/gold_labels.csv` must be provided by the user before Stage 13.

**Never fabricate labels.** Every example must be hand-labeled or verified by a human.
