# THREAT-SENSE AI

**Multi-layered cybersecurity threat detection platform.**  
Analyses URLs, domains, emails, SMS/messages, webpages, images, QR codes and files  
across **22 detectors** in **5 detection domains**, powered by shared reusable engines.

---

## Architecture

```
Input Artifact
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ AnalysisContext (lazy engine cache — each engine runs once)  │
│                                                              │
│  NLPEngine ──► SignalBackend (rules|zeroshot|finetuned|ens)  │
│  URLEngine ──► XGBoost model + SHAP + RapidFuzz              │
│  WebEngine ──► BeautifulSoup + YARA                          │
│  EmailEngine ► RFC822 + SPF/DKIM/DMARC                       │
│  MediaEngine ► QR decode + OCR                               │
│  IntelProvider► SafeBrowsing|VirusTotal|URLhaus|OpenPhish    │
└──────────────────────────────────────────────────────────────┘
      │
      ▼ (shared signals)
┌──────────────────────────────────────────────────────────────┐
│ 22 Detectors (thin composition layers)                       │
│  D1: Email Phishing, Social Engineering, Spear Phishing,     │
│      Scam/Fraud, Smishing, Gov Scams, Financial Scams,       │
│      Recruitment Scams, Tech Support Scams                   │
│  D2: Malicious URL, Brand Impersonation, Redirects,          │
│      URL Obfuscation, IDN/Homograph                          │
│  D3: Credential Harvesting, Fake Auth Pages, Malicious Pages  │
│  D4: BEC, Spam, Suspicious Attachments                       │
│  D5: QR Phishing, Screenshot Scam                            │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
RiskAggregator ──► RiskReport {risk_score 0-100, verdict, evidence}
```

---

## Quick Start

### Option A — Local (SQLite, no Docker)
```bash
# 1. Install
cd backend && pip install -e ".[dev]"

# 2. Run
uvicorn app.main:app --reload --port 8000

# 3. Test
pytest tests/ -v

# 4. Lint
ruff check app/ tests/
```

### Option B — Docker Compose (PostgreSQL)
```bash
# 1. Copy and edit env
cp .env.example .env

# 2. Start
docker compose up --build

# 3. API docs
open http://localhost:8000/docs
```

---

## Configuration Reference

All settings via environment variables (see `.env.example`).

| Variable | Default | Description |
|---|---|---|
| `NLP_BACKEND` | `rules` | `rules`\|`zeroshot`\|`finetuned`\|`ensemble` |
| `DATABASE_URL` | SQLite | Async SQLAlchemy URL |
| `LOG_LEVEL` | `INFO` | Python logging level |
| `GOOGLE_SAFE_BROWSING_API_KEY` | `` | Optional — degrades gracefully |
| `VIRUSTOTAL_API_KEY` | `` | Optional — degrades gracefully |
| `SEND_URLS_TO_THIRD_PARTIES` | `true` | Set `false` for privacy mode |

---

## Dataset Download

See [`ml/data/README.md`](ml/data/README.md) for all dataset sources, licences, and download instructions. **Never fabricate dataset metrics or labels.**

---

## Development Stages

| Stage | Focus | Status |
|---|---|---|
| 1 | Scaffold, schemas, registry | ✅ Done |
| 2 | Input layer + SafeFetcher | ⬜ |
| 3 | URL engine + XGBoost (D2) | ⬜ |
| 4 | NLP engine rules + zero-shot | ⬜ |
| 5 | Phishing & Social Eng (D1) | ⬜ |
| 6 | Web & Credential (D3) | ⬜ |
| 7 | Email & Communication (D4) | ⬜ |
| 8 | Multimedia (D5) | ⬜ |
| 9 | Threat intelligence | ⬜ |
| 10 | Risk aggregator + explainability | ⬜ |
| 11 | API hardening + React frontend | ⬜ |
| 12 | Evaluation, security, docs, demo | ⬜ |
| 13 | DeBERTa fine-tuning (last) | ⬜ |

---

## Adding a New Detector

1. Create `backend/app/detectors/dN_<domain>/<id>_<name>.py`
2. Subclass `BaseDetector`, decorate with `@register_detector`
3. Add an import to `backend/app/detectors/__init__.py`
4. Add fixtures to `backend/tests/fixtures/domainN/`
5. Run `make test` and `make lint`

---

## Security Notes

- **SafeFetcher** is the only component allowed to make outbound HTTP requests.  
  It blocks private/loopback/link-local IPs (SSRF), enforces timeouts, size caps,  
  redirect caps, and restricted schemes.
- **Attachments** are analysed statically only — never executed.
- **Never commit** real malware or API secrets.

See `docs/SECURITY.md` (Stage 12).
