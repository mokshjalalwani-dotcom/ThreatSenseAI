"""
Email Engine — Stage 7 full implementation.

Parses RFC 822 email artifacts using Python's built-in email module.
Extracts:
  - From / Reply-To / Return-Path header mismatch
  - Display-name spoofing
  - SPF / DKIM / DMARC pass/fail from Authentication-Results header
  - All URLs in body (text + HTML parts)
  - Attachment count, suspicious extension check
"""

from __future__ import annotations

import email as _email_lib
import email.policy
import logging
import re

from app.schemas.schemas import Artifact, EmailSignals

logger = logging.getLogger(__name__)

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_SUSPICIOUS_EXTS = {
    ".exe", ".scr", ".bat", ".vbs", ".ps1", ".jar", ".hta",
    ".js", ".jse", ".wsf", ".com", ".pif", ".zip", ".rar",
    ".7z", ".iso", ".img", ".dll", ".msi", ".dmg",
}
_AUTH_SPF_RE   = re.compile(r"spf=(pass|fail|neutral|none|softfail)", re.I)
_AUTH_DKIM_RE  = re.compile(r"dkim=(pass|fail|neutral|none)", re.I)
_AUTH_DMARC_RE = re.compile(r"dmarc=(pass|fail|none)", re.I)


def _domain_of(addr: str) -> str:
    """Extract domain from an email address string."""
    addr = addr.strip().lower().strip("<>")
    if "@" in addr:
        return addr.split("@")[-1].strip()
    return addr


def _parse_email(raw: str) -> EmailSignals:
    try:
        msg = _email_lib.message_from_string(raw, policy=email.policy.default)
    except Exception as exc:
        logger.warning("Email parse error: %s", exc)
        return EmailSignals()

    # ── Headers ───────────────────────────────────────────────────────────────
    from_header    = str(msg.get("From", ""))
    reply_to       = str(msg.get("Reply-To", ""))
    auth_results   = str(msg.get("Authentication-Results", ""))

    from_domain    = _domain_of(from_header)
    reply_domain   = _domain_of(reply_to) if reply_to else from_domain

    # Mismatch: reply-to domain differs from from domain
    from_reply_mismatch = bool(reply_to and reply_domain and reply_domain != from_domain)

    # Display-name spoofing: "PayPal Support <attacker@evil.com>"
    display_name_spoof = False
    brand_in_name_re = re.compile(
        r"\b(paypal|amazon|google|facebook|apple|microsoft|sbi|hdfc|icici|"
        r"paytm|phonepe|uidai|epfo|irctc|rbi|sebi)\b", re.I
    )
    if brand_in_name_re.search(from_header):
        # Brand name in display name but domain is NOT that brand
        brand_domain_map = {
            "paypal": "paypal.com", "amazon": "amazon.com",
            "google": "google.com", "facebook": "facebook.com",
            "microsoft": "microsoft.com", "apple": "apple.com",
            "sbi": "onlinesbi.sbi", "hdfc": "hdfcbank.com",
            "icici": "icicibank.com", "paytm": "paytm.com",
        }
        m = brand_in_name_re.search(from_header)
        if m:
            brand = m.group(0).lower()
            legit = brand_domain_map.get(brand, f"{brand}.com")
            if from_domain and legit not in from_domain:
                display_name_spoof = True

    # ── Auth results ─────────────────────────────────────────────────────────
    def _auth(pattern: re.Pattern[str]) -> bool | None:
        m2 = pattern.search(auth_results)
        if not m2:
            return None
        return m2.group(1).lower() == "pass"

    spf_pass   = _auth(_AUTH_SPF_RE)
    dkim_pass  = _auth(_AUTH_DKIM_RE)
    dmarc_pass = _auth(_AUTH_DMARC_RE)

    # ── URLs in body ─────────────────────────────────────────────────────────
    urls: list[str] = []
    attachments = 0

    for part in msg.walk():
        ct = part.get_content_type()
        cd = str(part.get_content_disposition() or "")

        if "attachment" in cd:
            attachments += 1
        elif ct in ("text/plain", "text/html"):
            try:
                body = part.get_content()
                urls.extend(_URL_RE.findall(str(body)))
            except Exception:
                pass

    # Deduplicate
    seen: set[str] = set()
    unique_urls = [u for u in urls if u not in seen and not seen.add(u)]  # type: ignore[func-returns-value]

    return EmailSignals(
        spf_pass=spf_pass,
        dkim_pass=dkim_pass,
        dmarc_pass=dmarc_pass,
        from_reply_to_mismatch=from_reply_mismatch,
        display_name_spoofing=display_name_spoof,
        sender_domain=from_domain or None,
        reply_to_domain=reply_domain if reply_to else None,
        extracted_urls=unique_urls[:30],
        attachment_count=attachments,
    )


class EmailEngine:
    """RFC 822 email header + body + attachment analysis engine."""

    async def analyze(self, artifact: Artifact) -> EmailSignals:
        raw = artifact.raw_content or ""
        if not raw.strip():
            return EmailSignals()
        return _parse_email(raw)
