# ThreatSenseAI — Detection Logic & Architecture Report

> **Version:** 0.1.0 · **NLP Backend:** Rules · **Detectors:** 22 · **Domains:** 5
> **Validation:** 10/10 test cases pass (100%) as of 2026-10-01

---

## 1. What "True" and "False" Mean in This Project

In the `examples/` folder:

| Folder | Meaning | Expected Verdict |
|--------|---------|-----------------|
| `examples/true/` | **Genuine, safe** artifacts — real, legitimate content | `safe` |
| `examples/false/` | **Fake, malicious** artifacts — crafted to deceive or attack | `malicious` / `likely_malicious` / `suspicious` |

This follows threat-intelligence convention:
- A **true** file is something that **truly is what it claims to be** (legitimate).
- A **false** file is something that **falsely pretends** to be legitimate but is actually a threat.

| File | Type | Expected | Validated Score |
|------|------|----------|----------------|
| `true/1_safe_url.txt` | URL | safe | 2.8 ✅ |
| `true/2_benign_email.eml` | Email | safe | 10.5 ✅ |
| `true/3_safe_sms.txt` | SMS | safe | 0.0 ✅ |
| `true/4_safe_webpage.html` | Webpage | safe | 11.0 ✅ |
| `true/5_safe_file.txt` | File | safe | 0.0 ✅ |
| `false/1_malicious_url.txt` | URL | likely_malicious | 70.0 ✅ |
| `false/2_phishing_email.eml` | Email | likely_malicious | 70.0 ✅ |
| `false/3_smishing_sms.txt` | SMS | likely_malicious | 70.0 ✅ |
| `false/4_fake_login_webpage.html` | Webpage | likely_malicious | 50.0 ✅ |
| `false/5_suspicious_file.bat` | File | likely_malicious | 70.0 ✅ |

---

## 2. Full Detection Pipeline

Every submission flows through **10 sequential stages**:

```
User submits artifact (URL / Email / SMS / Image / File / Webpage)
        ↓
Stage 1 : Upload Validation   (magic-byte MIME check, extension whitelist)
        ↓
Stage 2 : Normalization       (type-specific parser → canonical Artifact)
        ↓
Stages 3–7 : Engine Analysis  (NLP · URL · Web · Email · Media · Intel)
        ↓
Stages 8–9 : 22 Detectors     (consume engine signals, produce DetectionResults)
        ↓
Stage 10 : Risk Aggregator    (noisy-OR per domain → weighted sum → verdict)
        ↓
Final Verdict + Evidence Report
```

---

## 3. Stage 1 — Upload Validation (`uploader.py`)

Before any analysis the system validates the file:

- **Magic-byte MIME detection** — reads the first 8 bytes of the binary; ignores the declared extension to stop spoofing (`malware.exe → invoice.pdf`).
- **Extension whitelist** — verified against the selected artifact type.
- **OOXML passthrough** — `.docx/.xlsx/.pptx` are ZIP internally; the engine recognises them by content.
- **HTML allowed as both File and Webpage** — `.html/.htm/.xhtml` pass in either mode.
- **Executables allowed in File mode** — `.bat/.exe/.vbs` etc. are accepted so they can be *analysed*, not blocked.
- **Hard-blocked MIMEs** — `application/x-dosexec` (PE) and `application/x-executable` (ELF) are always rejected.

---

## 4. Stage 2 — Normalization

| Artifact Type | Normalizer | What It Extracts |
|--------------|-----------|-----------------|
| URL | `URLNormalizer` | Raw URL string |
| Email | `EmailNormalizer` | Headers, body text, HTML parts, extracted URLs, attachments |
| SMS | `SMSNormalizer` | Plain text + embedded HTTP URLs |
| Webpage | `WebpageNormalizer` | Full HTML, extracted href/action URLs, text content |
| Image | `ImageNormalizer` | Raw bytes, SHA-256, MIME from magic bytes |
| QR | `QRNormalizer` | Raw bytes → decoded QR payload |
| File | `FileNormalizer` | Raw bytes, double-extension detection, suspicious extension flag |

---

## 5. Stages 3–7 — Detection Engines

Results are cached in `AnalysisContext` — each engine runs exactly once per artifact regardless of how many detectors consume its signals.

### 5.1 NLP Engine (Rules Backend)

Analyses **text content** with a 15-signal deterministic lexicon + regex scorer. Zero ML, zero network, runs in < 1 ms.

Scoring formula per signal:
```
score = min(match_count × 0.25, 1.0)
```

| Signal | What It Detects | Example Keywords |
|--------|----------------|-----------------|
| `urgency` | Time-pressure tactics | "expire", "act now", "24 hours", "locked" |
| `fear` | Threats and intimidation | "warning", "suspended", "legal action", "arrested" |
| `authority` | Impersonation of officials | "RBI", "IRS", "FBI", "government", "court" |
| `reward_scarcity` | Too-good-to-be-true offers | "winner", "lottery", "prize", "free", "cashback" |
| `financial_intent` | Payment / money requests | "pay", "transfer", "bitcoin", "UPI", "crypto" |
| `credential_request` | Asking for sensitive info | "password", "OTP", "CVV", "Aadhaar", "login" |
| `manipulation` | Secrecy / trust manipulation | "don't tell", "100% safe", "guaranteed" |
| `phishing_intent` | Explicit phishing phrases | "click here to verify", "update your details" |
| `scam_intent` | Advance-fee and fraud phrases | "send money", "business proposal", "next of kin" |
| `payment_request` | Direct payment demands | "pay now", "scan QR", "use this UPI ID" |
| `remote_access_request` | Remote takeover attempts | "install AnyDesk", "share your screen" |
| `tech_support_context` | Fake IT support | "virus detected", "Windows support", "TeamViewer" |
| `investment_context` | Investment fraud | "guaranteed returns", "forex", "double your money" |
| `recruitment_context` | Fake job offers | "work from home", "earn from home", "urgent hiring" |
| `government_service_claim` | Fake government schemes | "income tax refund", "PM scheme", "IRS refund" |

Derived composite signals:
```python
phishing_intent = max(regex_match, (urgency + credential_request) / 2)
scam_intent     = max(regex_match, (fear + reward_scarcity) / 2)
```

### 5.2 URL Engine (Feature Extraction + Rule-Based Scoring)

Extracts a **28-dimensional feature vector** from the URL string alone (no network requests by default).

> **Critical rule (fixed bug):** The URL engine only receives a **real URL string** — never raw email body, HTML content, or plain SMS text. For EMAIL/SMS artifacts it uses the first extracted `http://` URL from the body. For WEBPAGE artifacts uploaded as files (no source URL), URL detectors are skipped entirely.

| Feature | Why It Matters |
|---------|---------------|
| `url_length` | Phishing URLs are typically very long |
| `subdomain_count` | `secure.bank.login.attacker.com` is a red flag |
| `is_https` | **Negative weight** — HTTPS is safer |
| `is_ip_host` | **Strong signal (+0.30)** — real sites use domain names |
| `has_punycode` | IDN homograph: `pаypal.com` (Cyrillic а) |
| `suspicious_token_count` | "login", "verify", "paypal", "amazon", "otp" in URL |
| `tld_risk` | `.xyz`=0.7, `.tk`=0.8, `.gov`=0.0, `.com`=0.1 |
| `has_at_sign` | `http://legit.com@evil.com` — browser visits `evil.com` |
| `has_hex_encoding` | `%61%70%70%6c%65.com` — hiding the real URL |
| `is_shortener` | `bit.ly`, `tinyurl.com` — destination is hidden |
| `path_has_exe` | `.exe`, `.bat`, `.php`, `.zip` in path |
| `dash_count` | `paypa1-secure-login.com` — dashes inflate suspicion |
| `entropy` | High entropy = random-looking URL = suspicious |

**Fallback scoring:** Linear rule-based scorer applies weights → sigmoid function → score in [0, 1]. XGBoost model used when available at `ml/artifacts/url_model/model.joblib`.

### 5.3 Web Engine (DOM Analysis)

> **Critical rule (fixed bug):** Only runs on `WEBPAGE` and `EMAIL` (HTML parts only). Never parses URL strings, SMS body, or plain-text email body as HTML.

Parses HTML with BeautifulSoup to detect:
- **Password / OTP / card fields** in `<input>` tags
- **Form action URL** pointing to an external domain
- **Form submitted over HTTP** (not HTTPS)
- **External script sources** from unknown domains
- **`eval()` / `document.write()` obfuscation** in `<script>` blocks
- **Brand name in page title** (e.g. "Microsoft Login" hosted on a non-Microsoft domain)
- **Link density** — phishing pages have many links but little real content

### 5.4 Email Engine (Header + Body Analysis)

For EMAIL artifacts only:
- **From / Reply-To domain mismatch** — a major phishing indicator
- **Display name spoofing** — `"PayPal Support" <attacker@evil.com>`
- **SPF / DKIM / DMARC** parsed from `Authentication-Results` header
- **Extracted URLs** from both `text/plain` and `text/html` MIME parts
- **Attachment metadata** — filename, declared vs detected MIME type

### 5.5 Media Engine (QR + OCR)

- **QR decoding** (`pyzbar`) — extracts embedded URL from QR code image
- **OCR** (`pytesseract`) — extracts text from images → runs full NLP pipeline

### 5.6 Intel Engine (External Threat Intelligence)

Optionally queries (requires API keys):
- **Google Safe Browsing** — known phishing/malware URLs
- **VirusTotal** — multi-engine URL/file reputation
- **AbuseIPDB** — IP address reputation
- **PhishTank** — crowdsourced phishing database

An Intel **hit** hard-overrides the final score to a minimum of **0.80** (MALICIOUS).

---

## 6. The 22 Detectors

### Domain 1: Phishing & Social Engineering (Weight: 30%)

| ID | Detector | Key Signals |
|----|---------|------------|
| D01 | Email Phishing | `phishing_intent` (0.35) + `credential_request` (0.25) + `urgency` (0.15) + header mismatches |
| D02 | Social Engineering | `manipulation` + `authority` + `fear` + `urgency` |
| D03 | Spear Phishing | Personalised targeting + `credential_request` |
| D04 | Scam & Fraud | `scam_intent` + `reward_scarcity` + `financial_intent` |
| D05 | Smishing | SMS-specific: short URL + urgency combo |
| D06 | Government Scams | `government_service_claim` + authority impersonation |
| D07 | Financial/Investment Fraud | `investment_context` + guaranteed returns + crypto |
| D08 | Recruitment Scams | `recruitment_context` + fake job language |
| D09 | Tech Support Scams | `tech_support_context` + `remote_access_request` |

### Domain 2: URL & Domain Security (Weight: 30%)

| ID | Detector | Key Signals |
|----|---------|------------|
| D10 | Malicious URL | URL risk score + suspicious tokens + TLD risk |
| D11 | Brand Impersonation | Known brand names in wrong domain context |
| D12 | Malicious Redirects | Redirect chains, `?url=` / `?redirect=` parameters |
| D13 | URL Obfuscation | Punycode, hex encoding, IP-as-host, @-sign, whitespace |
| D14 | IDN/Homograph Attack | Unicode lookalike characters in domain labels |

### Domain 3: Web & Credential Security (Weight: 20%)

| ID | Detector | Key Signals |
|----|---------|------------|
| D15 | Credential Harvesting | Login forms posting to external domains |
| D16 | Fake Authentication Pages | Password field + brand claim + external form action |
| D17 | Malicious Webpages | Iframes, eval() obfuscation, drive-by script links |

### Domain 4: Email & Communication Security (Weight: 15%)

| ID | Detector | Key Signals |
|----|---------|------------|
| D18 | Business Email Compromise | Header mismatches (0.25) + display spoofing (0.25) + SPF fail (0.15) + financial language |
| D19 | Spam | URL count ≥ 5 + SPF fail + reward/scam NLP signals |
| D20 | Suspicious Attachments | Double extension (0.90) + executable ext (0.85) + macro doc (0.45) + MIME mismatch (0.60) |

### Domain 5: Multimedia & Image-Based (Weight: 5%)

| ID | Detector | Key Signals |
|----|---------|------------|
| D21 | QR Code Phishing | Decoded QR URL → full URL + NLP analysis |
| D22 | Screenshot Scam | OCR text → full NLP pipeline |

---

## 7. Risk Aggregation (Stage 10)

### Step 1: Per-Domain Score — Noisy-OR
```
domain_score = 1 - ∏(1 - detector_score_i)
```
Multiple detectors firing amplify each other; a single strong signal is sufficient.

### Step 2: Weighted Overall Score
```
risk_score = Σ(domain_score_i × domain_weight_i) / Σ(domain_weight_i)
```

### Step 3: Hard Domain Floor (Fixed Bug)
Any **single domain** scoring ≥ 0.80 guarantees at least `likely_malicious`, regardless of inactive domain weights diluting the final score.

```
if max_domain_score ≥ 0.80 → raw_score = max(raw_score, 0.50)
if max_domain_score ≥ 0.60 → raw_score = max(raw_score, 0.25)
```

### Step 4: Hard Overrides
| Condition | Effect |
|-----------|--------|
| Intel hit (known malicious DB) | Score floored at **0.80** |
| Any CRITICAL severity evidence | Score floored at **0.70** |

### Step 5: Verdict Thresholds
| Risk Score | Verdict |
|-----------|---------|
| ≥ 75 | 🔴 MALICIOUS |
| 50–74 | 🟠 LIKELY MALICIOUS |
| 25–49 | 🟡 SUSPICIOUS |
| < 25 | 🟢 SAFE |

### Step 6: Confidence Calculation
```
confidence = 0.60 + (risk_score × 0.35)
```
- Score 0.0 (clean) → **60%** baseline confidence
- Score 1.0 (fully malicious) → **95%** confidence
- Penalised by 5% per engine error

---

## 8. Validated Example Walkthroughs

### `examples/true/1_safe_url.txt` → `https://www.google.com/`
- `is_https: 1.0` (negative weight −0.15)
- `suspicious_token_count: 0`
- `tld_risk: 0.10` (.com)
- **Final: 🟢 SAFE · score=2.8 · conf=63%**

### `examples/false/1_malicious_url.txt` → `http://secure-login-update-paypal-service.com/auth/verify.php`
- `suspicious_token_count: 5` (secure, login, update, paypal, verify)
- `dash_count: 4`
- `path_has_exe: 1.0` (.php)
- D10 score ≈ 0.94 → MALICIOUS
- D11 Brand Impersonation: "paypal" in wrong domain
- **Final: 🟠 LIKELY MALICIOUS · score=70.0 · conf=66%**

### `examples/false/2_phishing_email.eml`
- `urgency: 1.0` ("URGENT", "expires in 2 hours")
- `credential_request: 0.5` ("update your credentials")
- `fear: 0.5` ("locked out")
- D01 Email Phishing ≈ 0.60
- **Final: 🟠 LIKELY MALICIOUS · score=70.0 · conf=69%**

### `examples/true/2_benign_email.eml`
- No urgency, no credential requests, no URLs in body
- All D1/D2/D4 detectors score 0.0
- **Final: 🟢 SAFE · score=10.5 · conf=60%**

### `examples/false/4_fake_login_webpage.html`
- DOM: password field (`<input type="password">`) ✓
- DOM: form action → `http://evil-server.com/steal` ✓
- DOM: title claims "Microsoft 365 Login" on unknown domain ✓
- D15 Credential Harvesting: 0.65 · D16 Fake Auth Page: 0.575
- D3 domain score: 0.879 → hard floor kicks in → 0.50
- **Final: 🟠 LIKELY MALICIOUS · score=50.0 · conf=63%**

### `examples/false/5_suspicious_file.bat`
- Double extension check: `N/A`
- Extension `.bat` → `_SUSPICIOUS_EXTS` hit → score 0.85
- D20 Suspicious Attachments: `verdict=MALICIOUS`
- **Final: 🟠 LIKELY MALICIOUS · score=70.0 · conf=90%**

---

## 9. Bug Fix Log (Accuracy Issues Resolved)

### Bug 1 — D10/D11/D13: Raw content used as URL (Critical False Positives)

**Impact:** Benign emails, safe SMS, and safe webpages were scored as SUSPICIOUS or MALICIOUS.

**Root cause:** `artifact.raw_content` was used as the URL to analyse in all three URL detectors. For an EMAIL artifact, `raw_content` is the email body text (e.g. *"Hi everyone, the office is closed Monday…"*). Feeding a 500-character paragraph of text into the URL feature extractor produced:
- `url_length = 500` → high score
- `entropy = 4.5` → high score
- `whitespace detected` → "whitespace injection" false positive

**Fix:** Created `_resolve_url(artifact)` helper in each URL detector:
```python
def _resolve_url(artifact: Artifact) -> str:
    if artifact.type == ArtifactType.URL:
        return artifact.normalized_url or artifact.raw_content  # IS a URL
    if artifact.type in (EMAIL, SMS):
        return artifact.extracted_urls[0] if artifact.extracted_urls else ""
    if artifact.type == WEBPAGE:
        return artifact.normalized_url or ""  # skip file-uploaded HTML
    return ""
```

---

### Bug 2 — Web Engine: Parsed any text as HTML (False Positives)

**Impact:** URL strings and SMS body text were fed into BeautifulSoup, causing `MarkupResemblesLocatorWarning` and phantom DOM signals.

**Root cause:** `WebEngine.analyze()` used `artifact.raw_content` unconditionally. For a URL artifact like `https://www.google.com/`, BeautifulSoup was parsing the URL string as HTML.

**Fix:** Added type guard + HTML structure check:
```python
async def analyze(self, artifact: Artifact) -> WebSignals:
    if artifact.type not in (WEBPAGE, EMAIL):
        return WebSignals()   # skip all other types
    if not html.strip() or not html.startswith("<"):
        return WebSignals()   # skip non-HTML content
```

---

### Bug 3 — Aggregator: Domain weight dilution (False Negatives)

**Impact:** A fake login page with a D3 (Web Security) domain score of 0.879 was reported as SAFE (score 17.6) because the weighted average divided by all 5 domain weights, not just the active ones.

**Root cause:**
```
score = (0.879 × 0.20 D3 weight) / (0.30 + 0.30 + 0.20 + 0.15 + 0.05)
      = 0.176 / 1.0 = 17.6%   →  SAFE  ← WRONG
```

**Fix:** Added a hard domain floor — any single domain scoring ≥ 0.80 guarantees `likely_malicious`:
```python
max_domain_score = max(domain_scores.values(), default=0.0)
if max_domain_score >= 0.80:
    raw_score = max(raw_score, 0.50)   # floor at LIKELY_MALICIOUS
elif max_domain_score >= 0.60:
    raw_score = max(raw_score, 0.25)   # floor at SUSPICIOUS
```

---

## 10. Current Limitations

| Limitation | Impact |
|-----------|--------|
| NLP backend is **rules-only** (no ML model) | May miss novel phrasing not in keyword lists |
| OCR requires `tesseract` installed locally | Without it, Image/QR text extraction disabled |
| URL engine uses **rule-based fallback** by default | XGBoost model at `ml/artifacts/url_model/model.joblib` needs to be built with `make train-url-model` |
| Intel providers require **API keys** | Without keys, threat intelligence lookups skipped |
| Network features disabled by default | Domain age, DNS records not checked; enable with `ENABLE_NETWORK_FEATURES=true` |
| No live URL fetching | D12 Malicious Redirects relies on static URL analysis in offline mode |
| URL detectors skip uploaded HTML pages | File-uploaded webpages with no source URL cannot be scored by D10/D11/D13 |
