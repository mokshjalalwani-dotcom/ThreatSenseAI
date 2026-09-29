# 🛡️ ThreatSense AI

**ThreatSense AI** is a multi-layered cybersecurity threat detection platform designed to protect users against phishing, social engineering, malicious webpages, credential harvesting, and more. 

It analyses **URLs, Emails, SMS, Webpages, Images, QR codes, and Files** across **22 specialized detectors** spanning **5 threat domains**.

![ThreatSense AI Dashboard Dashboard Mockup](https://via.placeholder.com/1000x500.png?text=ThreatSense+AI+Dashboard)

## 🚀 Features

* **Multi-modal Analysis:** Submit raw URLs, `.eml` files, plain text SMS, images containing text or QR codes, or complete HTML documents.
* **5 Intelligence Engines:**
  * **NLP Engine:** 15-signal lexicon and regex rule scorer to detect urgency, fear, manipulation, financial intent, etc.
  * **URL/Web Engine:** Parses DOM elements (BeautifulSoup) for fake auth pages, hidden password fields, and JS obfuscation. Calculates Levenshtein distances for brand impersonation.
  * **Email Engine:** Validates SPF/DKIM/DMARC headers, checks for display name spoofing, and extracts hidden URLs.
  * **Media Engine:** Asynchronous QR code decoding (pyzbar) and OCR (pytesseract) for screenshot-based scams.
  * **Intel Engine:** Lookups against local blocklists (Domains, IPs, Hashes) and live integrations (URLhaus).
* **Risk Aggregator:** Uses a noisy-OR probability combination model weighted by threat severity, with critical evidence floors.
* **Modern Dashboard:** A premium, dark-mode React + Vite frontend dashboard displaying animated risk scores, domain breakdowns, and severity-badged evidence lists.

## 🛠️ Architecture

* **Backend:** FastAPI, SQLAlchemy (SQLite/Postgres), Alembic, Pydantic, Beautifulsoup4, Pyzbar, Pytesseract.
* **Frontend:** React, Vite, standard CSS (Glassmorphism design).
* **Design Pattern:** Detector Registry pattern. Engines extract signals, Detectors consume signals to output verdicts, and the Aggregator normalizes the final score.

---

## 🏃‍♂️ Running Locally

### Prerequisites
* Python 3.11+
* Node.js 18+
* `tesseract-ocr` and `libzbar0` installed on your system (for Media Engine).

### 1. Start the Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
uvicorn app.main:app --reload --port 8000
```
*API Docs available at: `http://localhost:8000/docs`*

### 2. Start the Frontend
```bash
cd frontend
npm install
npm run dev
```
*Dashboard available at: `http://localhost:5173`*

---

## ☁️ Deployment

ThreatSense AI is fully containerized and includes Infrastructure-as-Code blueprints for instant deployment on free-tier platforms.

### 1. Backend (Render.com)
The repository contains a `render.yaml` Blueprint.
1. Sign in to [Render](https://render.com/).
2. Create a **New Blueprint Instance**.
3. Select this repository.
4. Render will automatically provision a Docker web service using the backend `Dockerfile`. (Uses an ephemeral SQLite database by default).

### 2. Frontend (Vercel)
1. Sign in to [Vercel](https://vercel.com/).
2. Import this repository.
3. Set the **Framework Preset** to `Vite` and the **Root Directory** to `frontend`.
4. Under **Environment Variables**, add:
   * `VITE_API_URL` = `https://<your-render-backend-url>.onrender.com` (No trailing slash)
5. Deploy.

---

## 🧪 Testing

The backend includes a comprehensive pytest suite (396 tests).
```bash
cd backend
pytest tests/ -q --tb=short
```

## ⚖️ License
MIT License
