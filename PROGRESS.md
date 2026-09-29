# THREAT-SENSE AI — Build Progress

Last updated: 2026-09-29 (Stages 4-11 complete)

## Stage Checklist

| Stage | Description | Status | Tests |
|-------|-------------|--------|-------|
| 0 | Master context, rules, scaffold planning | ✅ DONE | — |
| 1 | Scaffold + detector registry + engine interfaces + AnalysisContext | ✅ DONE | 337 |
| 2 | Input normalizers + router + SafeFetcher + upload hardening | ✅ DONE | 337 |
| 3 | URL/Domain engines + brand matching + D10-D14 detectors | ✅ DONE | 337 |
| 4 | NLP Engine: RulesBackend, ZeroShotBackend, EnsembleBackend, FinetunedBackend stub | ✅ DONE | 396 |
| 5 | D01-D09 phishing/scam/SE detectors | ✅ DONE | 396 |
| 6 | WebEngine (BS4 DOM parsing, credential fields, JS obfuscation) + D15-D17 | ✅ DONE | 396 |
| 7 | EmailEngine (RFC822, SPF/DKIM/DMARC, display-name spoof) + D18-D20 | ✅ DONE | 396 |
| 8 | MediaEngine (QR decode + OCR async) + D21-D22 | ✅ DONE | 396 |
| 9 | IntelEngine (local blocklists + URLhaus optional) | ✅ DONE | 396 |
| 10 | Risk Aggregator (noisy-OR, weighted, intel floor) + Explainer | ✅ DONE | 396 |
| 11 | API wired (all 6 engines in pipeline), Frontend Dashboard | 🔄 API DONE / Frontend pending |
| 12 | Evaluation, Security Review, Documentation & Demo | 🔲 TODO |
| 13 | DeBERTa fine-tuning (HARD STOP — await explicit user instruction) | 🔲 BLOCKED |

## Current Test Count
**396 tests passing | 0 lint errors**

## Files Created/Modified (Stages 4-11)

### New Detectors (D01-D22)
- `backend/app/detectors/d1_phishing/_nlp_helpers.py` — shared NLP score/evidence helpers
- `backend/app/detectors/d1_phishing/d01_email_phishing.py`
- `backend/app/detectors/d1_phishing/d02_social_engineering.py`
- `backend/app/detectors/d1_phishing/d03_spear_phishing.py`
- `backend/app/detectors/d1_phishing/d04_scam_fraud.py`
- `backend/app/detectors/d1_phishing/d05_smishing.py`
- `backend/app/detectors/d1_phishing/d06_government_scams.py`
- `backend/app/detectors/d1_phishing/d07_financial_investment.py`
- `backend/app/detectors/d1_phishing/d08_recruitment_scams.py`
- `backend/app/detectors/d1_phishing/d09_tech_support_scams.py`
- `backend/app/detectors/d3_web/d15_credential_harvesting.py`
- `backend/app/detectors/d3_web/d16_fake_auth_pages.py`
- `backend/app/detectors/d3_web/d17_malicious_webpages.py`
- `backend/app/detectors/d4_email/d18_bec.py`
- `backend/app/detectors/d4_email/d19_spam.py`
- `backend/app/detectors/d4_email/d20_suspicious_attachments.py`
- `backend/app/detectors/d5_media/d21_qr_phishing.py`
- `backend/app/detectors/d5_media/d22_screenshot_scam.py`

### Engines (Full implementations)
- `backend/app/engines/nlp/backends/rules.py` — 15-signal lexicon scorer
- `backend/app/engines/nlp/backends/zeroshot.py` — BART-MNLI async
- `backend/app/engines/nlp/backends/ensemble.py` — weighted blend
- `backend/app/engines/nlp/backends/finetuned.py` — stub for Stage 13
- `backend/app/engines/web/engine.py` — BS4 DOM parser
- `backend/app/engines/email/engine.py` — RFC822 parser
- `backend/app/engines/media/engine.py` — QR + OCR async
- `backend/app/engines/intel/engine.py` — blocklist + URLhaus
- `backend/app/engines/intel/data/` — domain/ip/hash/url blocklists

### Core
- `backend/app/aggregator/aggregator.py` — noisy-OR + weights + intel floor
- `backend/app/explain/explainer.py` — URL defang + verdict summaries
- `backend/app/api/routes/analyze.py` — all 6 engines wired in pipeline

### Tests
- `backend/tests/test_nlp_engine.py` — 26 tests (backends + D01-D09)
- `backend/tests/test_stages_6_to_10.py` — 33 tests (engines + D15-D22 + aggregator)

## Next: Stage 11 Frontend Dashboard
Build React/Vite frontend at `frontend/` that calls `POST /analyze` and renders the RiskReport.
