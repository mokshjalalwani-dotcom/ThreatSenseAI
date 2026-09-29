"""
Web/DOM Engine — Stage 6 full implementation.

Parses HTML with BeautifulSoup to extract credential-harvesting signals:
  - Password / OTP / card fields
  - Form action URL analysis (external domain, HTTP vs HTTPS)
  - External script sources
  - eval() / document.write obfuscation
  - Page title and claimed brand heuristic
  - Link density (many links = low content, possible phish page)
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from app.schemas.schemas import Artifact, WebSignals

logger = logging.getLogger(__name__)

# Field name patterns
_PASSWORD_RE   = re.compile(r"pass(word)?|passwd|pwd|secret", re.I)
_OTP_RE        = re.compile(r"\botp\b|one.time|pin\b|verification.code", re.I)
_CARD_RE       = re.compile(r"card.?number|cvv|cvc|expir|ccnum|creditcard", re.I)
_EVAL_RE       = re.compile(r"\beval\s*\(|document\.write\s*\(|unescape\s*\(", re.I)
_BRAND_RE      = re.compile(
    r"\b(paypal|amazon|google|facebook|apple|microsoft|netflix|ebay|"
    r"sbi|hdfc|icici|axis|paytm|phonepe|gpay|uidai|epfo|irctc)\b", re.I
)


def _parse_html(html: str) -> WebSignals:
    """Parse raw HTML and return WebSignals. Falls back to empty on any error."""
    try:
        from bs4 import BeautifulSoup  # type: ignore[import]
    except ImportError:
        logger.warning("BeautifulSoup not installed — WebEngine returning empty signals")
        return WebSignals()

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as exc:
        logger.warning("HTML parse error: %s", exc)
        return WebSignals()

    has_password_field = False
    has_otp_field      = False
    has_card_field     = False
    form_external      = False
    form_over_http     = False
    has_eval           = False
    external_scripts: list[str] = []
    claimed_brand: str | None = None

    # ── Input fields ──────────────────────────────────────────────────────────
    for inp in soup.find_all("input"):
        itype = (inp.get("type") or "").lower()
        iname = (inp.get("name") or "") + (inp.get("id") or "") + (inp.get("placeholder") or "")
        if itype == "password" or _PASSWORD_RE.search(iname):
            has_password_field = True
        if _OTP_RE.search(iname):
            has_otp_field = True
        if _CARD_RE.search(iname):
            has_card_field = True

    # ── Forms ─────────────────────────────────────────────────────────────────
    page_domain = ""
    canonical = soup.find("link", rel="canonical")
    if canonical and canonical.get("href"):
        page_domain = urlparse(canonical["href"]).netloc

    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action:
            parsed = urlparse(action)
            if parsed.scheme == "http":
                form_over_http = True
            if parsed.netloc and page_domain and parsed.netloc != page_domain:
                form_external = True

    # ── External scripts ──────────────────────────────────────────────────────
    for script in soup.find_all("script", src=True):
        src = script.get("src", "")
        p = urlparse(src)
        if p.netloc and page_domain and p.netloc != page_domain:
            external_scripts.append(p.netloc)

    # ── JavaScript obfuscation ────────────────────────────────────────────────
    for script in soup.find_all("script"):
        code = script.string or ""
        if _EVAL_RE.search(code):
            has_eval = True
            break

    # ── Brand claim ───────────────────────────────────────────────────────────
    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else ""
    m = _BRAND_RE.search(title)
    if not m:
        # Also check H1
        h1 = soup.find("h1")
        if h1:
            m = _BRAND_RE.search(h1.get_text())
    if m:
        claimed_brand = m.group(0).lower()

    # ── Link density ──────────────────────────────────────────────────────────
    all_text = soup.get_text(separator=" ")
    all_links = soup.find_all("a", href=True)
    word_count = max(1, len(all_text.split()))
    link_density = round(len(all_links) / word_count, 4)

    return WebSignals(
        has_password_field=has_password_field,
        has_otp_field=has_otp_field,
        has_card_field=has_card_field,
        form_posts_to_external_domain=form_external,
        form_action_over_http=form_over_http,
        external_script_domains=list(set(external_scripts))[:10],
        claimed_brand=claimed_brand,
        title=title[:200] if title else None,
        link_density=link_density,
        has_eval_obfuscation=has_eval,
    )


class WebEngine:
    """HTML/DOM and credential-field analysis engine."""

    async def analyze(self, artifact: Artifact) -> WebSignals:
        html = artifact.raw_content or ""
        if not html.strip():
            return WebSignals()
        return _parse_html(html)
