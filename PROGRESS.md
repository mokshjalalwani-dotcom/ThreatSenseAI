# THREAT-SENSE AI — Stage Progress

> Updated automatically after each stage. If this session is interrupted, resume from the last ✅ entry.

## Stages

| # | Title | Status | Report |
|---|---|---|---|
| 0 | Master Context / Project Rules | ✅ Done | — |
| 1 | Scaffold: schemas, registry, 22 stubs, AnalysisContext | ✅ Done | STAGE_1_REPORT.md |
| 2 | Input handling: normalizers, router, SafeFetcher, upload hardening | ✅ Done | STAGE_2_REPORT.md |
| 3 | URL/Domain Engine + Detectors 10–14 | ✅ Done | STAGE_3_REPORT.md |
| 4 | Shared NLP Engine (rules + zeroshot) | ⏳ Pending | — |
| 5 | Domain 1: Phishing & Social Engineering (D01–D09) | ⏳ Pending | — |
| 6 | Domain 3: Web & Credential Security (D15–D17) | ⏳ Pending | — |
| 7 | Domain 4: Email & Communication Security (D18–D20) | ⏳ Pending | — |
| 8 | Domain 5: Multimedia & Image-Based Threats (D21–D22) | ⏳ Pending | — |
| 9 | Threat Intelligence Enrichment | ⏳ Pending | — |
| 10 | Risk Aggregator & Explainability | ⏳ Pending | — |
| 11 | API Hardening & Frontend Dashboard | ⏳ Pending | — |
| 12 | Evaluation, Security Review, Documentation & Demo | ⏳ Pending | — |
| 13 | DeBERTa Fine-Tuning **(HARD STOP — explicit "start Stage 13" required)** | 🔒 Locked | — |

---

## Stage 3 Detail Checklist

- [x] URL feature extractor (`features.py`) — 28 structural + 5 network features
- [x] URLEngine updated — model inference + rule-based fallback
- [x] Brand YAML + TLD-risk config in `features.py`
- [x] D10 MaliciousURL — model-backed + rule fallback + SHAP
- [x] D11 BrandImpersonation — tldextract roots, fuzz.ratio, leet normalization, no FPs
- [x] D12 MaliciousRedirects — SafeFetcher chain analysis + shortener detection
- [x] D13 URLObfuscation — encoding decode, @-trick, octal/hex/decimal IP, entropy
- [x] D14 IDN/Homograph — xn-- decode, confusables, skeleton check
- [x] Download script `ml/training/download_url_data.py`
- [x] Training script `ml/training/train_url_model.py`
- [x] ml/data/README.md updated with dataset sources + licences
- [x] ml/artifacts/url_model/REPORT.md
- [x] Test fixtures (≥15 positive + ≥15 negative per detector)
- [x] test_url_engine.py  (80 tests)
- [x] test_d2_detectors.py  (159 tests)
- [x] STAGE_3_REPORT.md
- [x] make test green — **337/337 passed**
- [x] make lint green — **0 ruff errors**

---

## Key Decisions Logged

| Decision | Stage | Rationale |
|---|---|---|
| Class decorator for registration | 1 | Explicit, debuggable |
| Double-checked async lock per engine key | 1 | Concurrent-safe, zero-overhead after first call |
| Normalizers never raise — partial Artifact | 2 | Pipeline resilience |
| Manual redirect following in SafeFetcher | 2 | SSRF re-check on every hop |
| D10 mini-synthetic model for CI; real model via `make train-url-model` | 3 | CI must not require internet/downloads |
| Network features disabled by default (ENABLE_NETWORK_FEATURES=false) | 3 | Offline-first; RDAP/DNS calls are optional |
| URLhaus optional (free Auth-Key needed) | 3 | Documented; not required for system to work |

---

## Pause Points

| After | Action |
|---|---|
| Stage 5 | 10-line status summary — wait for "continue" |
| Stage 8 | 10-line status summary — wait for "continue" |
| Stage 10 | 10-line status summary — wait for "continue" |
| Stage 12 | STOP — wait for explicit "start Stage 13" |
