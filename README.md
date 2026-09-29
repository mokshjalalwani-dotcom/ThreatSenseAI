<div align="center">

# 🛡️ ThreatSense AI

**Multi-layered cybersecurity threat detection platform**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react)](https://react.dev)
[![Tests](https://img.shields.io/badge/Tests-396%20passing-22c55e?style=flat-square&logo=pytest)](./backend/tests)
[![Detectors](https://img.shields.io/badge/Detectors-22-6366f1?style=flat-square)](./backend/app/detectors)
[![License](https://img.shields.io/badge/License-MIT-gray?style=flat-square)](./LICENSE)

Analyses URLs · Emails · SMS · Webpages · Images · QR Codes · Files  
across **22 specialized detectors** in **5 threat domains** — all in real time.

</div>

---

## 📸 Dashboard

> Dark-mode React dashboard — submit any artifact and get an annotated risk report in seconds.

![Dashboard](https://via.placeholder.com/900x480/0a0e1a/6366f1?text=ThreatSense+AI+Dashboard+%E2%80%94+Coming+Soon)

---

## ✨ Features

| | Feature | Details |
|---|---|---|
| 🔗 | **URL Analysis** | Entropy scoring, Levenshtein brand impersonation, suspicious TLD/redirect chain detection |
| 📧 | **Email Analysis** | SPF / DKIM / DMARC validation, display-name spoofing, BEC & attachment scanning |
| 💬 | **SMS / Message Analysis** | 15-signal NLP engine — urgency, fear, financial intent, credential requests |
| 🌐 | **Webpage Analysis** | DOM parsing for hidden password fields, JS obfuscation (`eval`, `document.write`), fake auth pages |
| 🖼️ | **Image / QR Analysis** | Async QR decode (pyzbar) + OCR (pytesseract) to detect screenshot-based scams |
| 🗃️ | **Threat Intelligence** | Local blocklists (domains, IPs, hashes, URLs) + live URLhaus API lookup |
| 📊 | **Risk Aggregation** | Noisy-OR probability model, domain-weighted scoring, critical-evidence floor at 70/100 |
| 💡 | **Explainer** | Human-readable verdict summaries, URL defanging, redirect chain rendering |
| ⚡ | **Speed** | Pure rules engine by default — <50ms per analysis, no GPU required |

---

## 🧠 Detection Domains & Detectors

<details>
<summary><b>Domain 1 — Phishing & Social Engineering (9 detectors)</b></summary>

| ID | Detector | Catches |
|----|----------|---------|
| D01 | Email Phishing | Credential theft via email lures |
| D02 | Social Engineering | Emotional manipulation tactics |
| D03 | Spear Phishing | Targeted, personalised attacks |
| D04 | Scam & Fraud | Prize, lottery, advance-fee scams |
| D05 | Smishing | SMS phishing with shortlinks |
| D06 | Government Scams | Fake HMRC, IRS, Aadhaar, passport |
| D07 | Financial Investment | Fake trading platforms, pump-and-dump |
| D08 | Recruitment Scams | Fake job offers requiring upfront payment |
| D09 | Tech Support Scams | Fake Microsoft/Apple remote-access lures |
</details>

<details>
<summary><b>Domain 2 — Malicious URLs (5 detectors)</b></summary>

| ID | Detector | Catches |
|----|----------|---------|
| D10 | Typosquatting | Lookalike domains (paypa1.com) |
| D11 | URL Shortener Abuse | bit.ly, tinyurl wrapping malicious links |
| D12 | Homoglyph Attack | Unicode character substitution |
| D13 | Redirect Chains | Multi-hop cloaking |
| D14 | Suspicious TLD | .xyz, .top, .click, .zip abuse |
</details>

<details>
<summary><b>Domain 3 — Malicious Webpages (3 detectors)</b></summary>

| ID | Detector | Catches |
|----|----------|---------|
| D15 | Credential Harvesting | Hidden password/card fields |
| D16 | Fake Auth Pages | Brand-spoofed login pages |
| D17 | Malicious Webpages | JS obfuscation, drive-by exploit patterns |
</details>

<details>
<summary><b>Domain 4 — Email Threats (3 detectors)</b></summary>

| ID | Detector | Catches |
|----|----------|---------|
| D18 | Business Email Compromise | From/Reply-To mismatch + financial ask |
| D19 | Spam | Bulk unsolicited email patterns |
| D20 | Suspicious Attachments | Double-extension, macro-enabled, MIME mismatch |
</details>

<details>
<summary><b>Domain 5 — Media Threats (2 detectors)</b></summary>

| ID | Detector | Catches |
|----|----------|---------|
| D21 | QR Phishing (Quishing) | Malicious URLs embedded in QR codes |
| D22 | Screenshot Scam | OCR-extracted text analysed for scam content |
</details>

---

## 🏗️ Architecture

```
ThreatSenseAI/
├── backend/                   # FastAPI backend
│   ├── app/
│   │   ├── api/routes/        # /analyze, /health, /detectors endpoints
│   │   ├── core/              # Config, logging, detector registry
│   │   ├── db/                # SQLAlchemy models + async session
│   │   ├── engines/           # 5 intelligence engines
│   │   │   ├── nlp/           #   NLP (rules, zero-shot, ensemble, fine-tuned stub)
│   │   │   ├── url/           #   URL/domain analysis
│   │   │   ├── web/           #   DOM analysis (BeautifulSoup)
│   │   │   ├── email/         #   RFC 822 email parsing
│   │   │   ├── media/         #   QR decode + OCR (async)
│   │   │   └── intel/         #   Blocklists + URLhaus
│   │   ├── detectors/         # 22 detectors (D01–D22)
│   │   ├── aggregator/        # Noisy-OR risk scorer
│   │   └── explain/           # Human-readable report builder
│   ├── alembic/               # DB migrations
│   ├── tests/                 # 396 pytest tests
│   └── Dockerfile
├── frontend/                  # React + Vite dashboard
│   └── src/
│       ├── App.jsx            # Main dashboard component
│       └── index.css          # Premium dark-mode styling
├── render.yaml                # Render.com deployment blueprint
└── README.md
```

**Request lifecycle:**
```
POST /analyze
  → Normalizer (type + content validation)
  → SafeFetcher (SSRF-safe HTTP client, if URL)
  → AnalysisContext built
  → 5 Engines run in parallel (NLP · URL · Web · Email · Media · Intel)
  → 22 Detectors consume engine signals
  → Risk Aggregator (noisy-OR per domain → weighted final score)
  → Explainer (defang URLs, build verdict summary)
  → RiskReport persisted to DB → returned as JSON
```

---

## 🚀 Running Locally

### Prerequisites
- Python 3.11+
- Node.js 18+
- `tesseract-ocr` and `libzbar0` (for image/QR analysis)
  ```bash
  # Ubuntu/Debian
  sudo apt install tesseract-ocr libzbar0
  # macOS
  brew install tesseract zbar
  # Windows — install from https://github.com/UB-Mannheim/tesseract/wiki
  ```

### Backend
```bash
cd backend
pip install -e .
uvicorn app.main:app --reload --port 8000
```
API docs: **http://localhost:8000/docs**

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Dashboard: **http://localhost:5173**

> The frontend automatically connects to `http://localhost:8000`. No config needed for local dev.

---

## ☁️ Deployment

### Backend → [Render.com](https://render.com) (Free Tier)

This repo includes a `render.yaml` Blueprint. Just:

1. Go to Render → **New +** → **Blueprint**
2. Connect this GitHub repository
3. Click **Apply** — done! ✅

Render builds the Docker container, installs all dependencies (including Tesseract OCR), and starts the API.

> ⚠️ **Free tier note:** Your service will spin down after 15 min of inactivity. The first request after that takes ~50s to wake up.

### Frontend → [Vercel](https://vercel.com) (Free Tier)

1. Go to Vercel → **Add New Project** → import this repository
2. Set **Root Directory** to `frontend`
3. **Framework Preset** → `Vite`
4. Add Environment Variable:
   | Key | Value |
   |-----|-------|
   | `VITE_API_URL` | `https://your-render-service.onrender.com` |
5. Click **Deploy** ✅

---

## 🧪 Tests

```bash
cd backend
pytest tests/ -q --tb=short
# 396 passed in ~7s
```

Test coverage spans all 22 detectors, all 5 engines, the aggregator, explainer, API routes, URL normalizers, and safe-fetcher.

---

## 🗺️ Roadmap

- [x] Stage 1–3: Scaffold, registry, engine interfaces, URL/domain detectors (D10–D14)
- [x] Stage 4: NLP Engine (rules, zero-shot, ensemble backends)
- [x] Stage 5: Phishing/SE detectors (D01–D09)
- [x] Stage 6–8: Web, Email, Media engines + D15–D22
- [x] Stage 9: Intel Engine (blocklists + URLhaus)
- [x] Stage 10: Risk Aggregator + Explainer
- [x] Stage 11: API wired + React dashboard
- [ ] Stage 12: Evaluation dataset, security review, extended docs
- [ ] Stage 13: DeBERTa fine-tuned NLP backend (improves recall ~15%)

---

## 📜 License

MIT © 2026 ThreatSense AI Contributors
