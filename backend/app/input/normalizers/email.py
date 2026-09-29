"""Email (.eml / raw RFC822) input normalizer."""

from __future__ import annotations

import email
import email.policy
import logging
from email.header import decode_header, make_header

from app.input.normalizers.base import BaseNormalizer
from app.input.normalizers.utils import (
    detect_mime_from_magic,
    extract_urls,
    get_extension,
    is_suspicious_extension,
    sha256_hex,
)
from app.schemas.schemas import Artifact, ArtifactType, AttachmentInfo

logger = logging.getLogger(__name__)

_POLICY = email.policy.EmailPolicy(
    utf8=True,
    refold_source="none",
    max_line_length=None,
)


def _decode_header_value(raw: str | None) -> str:
    """Decode a potentially RFC-2047 encoded header value to plain text."""
    if not raw:
        return ""
    try:
        return str(make_header(decode_header(raw)))
    except Exception:
        return raw or ""


class EmailNormalizer(BaseNormalizer):
    """RFC-822 email normalizer.

    Parses raw .eml text (or bytes) into a canonical Artifact that contains:
      - Plain-text body in raw_content (HTML converted via html2text)
      - All URLs extracted from both text and HTML bodies
      - Sender, reply-to, subject, return-path in metadata
      - AttachmentInfo records for every MIME attachment

    Child Artifact objects for attachments are created and placed in
    `Artifact.attachments`.  Their raw bytes are stored in metadata
    ``["attachment_bytes"]`` keyed by sha256 (caller should move them to
    child Artifacts if needed for deep inspection).
    """

    artifact_type = ArtifactType.EMAIL

    def normalize(self, raw: str | bytes, **kwargs: object) -> Artifact:
        if isinstance(raw, bytes):
            raw_str = raw.decode("utf-8", errors="replace")
        else:
            raw_str = raw

        try:
            msg = email.message_from_string(raw_str, policy=email.policy.compat32)
        except Exception as exc:
            logger.warning("EmailNormalizer: failed to parse email: %s", exc)
            return Artifact(
                type=ArtifactType.EMAIL,
                raw_content=raw_str,
                metadata={"parse_error": str(exc)},
            )

        # ── Headers ──────────────────────────────────────────────────────────
        from_header = _decode_header_value(msg.get("From", ""))
        reply_to = _decode_header_value(msg.get("Reply-To", ""))
        return_path = _decode_header_value(msg.get("Return-Path", ""))
        subject = _decode_header_value(msg.get("Subject", ""))
        to_header = _decode_header_value(msg.get("To", ""))
        date = _decode_header_value(msg.get("Date", ""))
        message_id = _decode_header_value(msg.get("Message-ID", ""))

        # ── Authentication headers ────────────────────────────────────────────
        spf_result = msg.get("Received-SPF", "")
        dkim_result = msg.get("DKIM-Signature", "")
        auth_results = msg.get("Authentication-Results", "")

        # ── Body and attachments ──────────────────────────────────────────────
        text_parts: list[str] = []
        html_parts: list[str] = []
        attachments: list[AttachmentInfo] = []
        attachment_bytes: dict[str, bytes] = {}

        for part in msg.walk():
            ct = part.get_content_type()
            disposition = part.get("Content-Disposition", "")
            filename = part.get_filename()

            if filename or "attachment" in disposition:
                # ── Attachment ────────────────────────────────────────────────
                payload: bytes = part.get_payload(decode=True) or b""
                fname = _decode_header_value(filename) if filename else "unnamed"
                ext = get_extension(fname)
                detected = detect_mime_from_magic(payload) if payload else None
                digest = sha256_hex(payload) if payload else ""
                suspicious = is_suspicious_extension(fname)

                att = AttachmentInfo(
                    filename=fname,
                    declared_mime=ct,
                    detected_mime=detected,
                    extension=ext,
                    size_bytes=len(payload),
                    sha256=digest,
                    is_suspicious_extension=suspicious,
                )
                attachments.append(att)
                if payload:
                    attachment_bytes[digest] = payload

            elif ct == "text/plain" and "attachment" not in disposition:
                payload_bytes: bytes = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                text_parts.append(payload_bytes.decode(charset, errors="replace"))

            elif ct == "text/html" and "attachment" not in disposition:
                payload_bytes = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                html_raw = payload_bytes.decode(charset, errors="replace")
                html_parts.append(html_raw)
                # Convert HTML → text for NLP processing
                text_parts.append(_html_to_text(html_raw))

        full_text = "\n\n".join(text_parts).strip()

        # ── URL extraction ────────────────────────────────────────────────────
        extracted_urls = extract_urls(full_text)
        for html_body in html_parts:
            extracted_urls.extend(_extract_href_urls(html_body))
        # Deduplicate while preserving order
        seen: set[str] = set()
        deduped_urls: list[str] = []
        for u in extracted_urls:
            if u not in seen:
                seen.add(u)
                deduped_urls.append(u)

        return Artifact(
            type=ArtifactType.EMAIL,
            raw_content=full_text,
            extracted_urls=deduped_urls,
            attachments=attachments,
            metadata={
                "from": from_header,
                "reply_to": reply_to,
                "return_path": return_path,
                "subject": subject,
                "to": to_header,
                "date": date,
                "message_id": message_id,
                "spf_result": spf_result,
                "dkim_signature_present": bool(dkim_result),
                "auth_results": auth_results,
                "html_bodies": html_parts,
                "attachment_bytes": attachment_bytes,  # sha256 → bytes map
                "attachment_count": len(attachments),
            },
        )


def _html_to_text(html: str) -> str:
    """Convert HTML to plain text via html2text (if available) or BS4."""
    try:
        import html2text as h2t

        handler = h2t.HTML2Text()
        handler.ignore_links = False
        handler.ignore_images = True
        handler.body_width = 0
        return handler.handle(html)
    except ImportError:
        pass

    try:
        from bs4 import BeautifulSoup

        return BeautifulSoup(html, "html.parser").get_text(separator="\n")
    except ImportError:
        pass

    # Fallback: strip tags naively
    import re

    return re.sub(r"<[^>]+>", " ", html)


def _extract_href_urls(html: str) -> list[str]:
    """Extract href= and src= URLs from HTML."""
    import re

    return re.findall(
        r'(?:href|src|action)=["\']?(https?://[^"\'\s>]+)', html, re.IGNORECASE
    )
