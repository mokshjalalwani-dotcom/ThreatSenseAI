"""
Input normalizer unit tests.

Acceptance criteria:
  ✓ Email: sample.eml parsed into correct Artifact tree
      - exactly 2 URLs extracted
      - exactly 1 attachment with correct metadata
      - from/subject/reply-to headers captured
  ✓ URL: canonical form correct, components extracted
  ✓ SMS: URLs extracted, phone numbers found
  ✓ Webpage: href links extracted, title captured
  ✓ Image: Pillow validates PNG; SHA-256 computed; oversized rejected
  ✓ File: SHA-256, MIME detection, suspicious extension flagged
  ✓ Uploader: blocked MIME, oversized, bad extension raise UploadValidationError
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest

from app.input.normalizers.email import EmailNormalizer
from app.input.normalizers.file import FileNormalizer
from app.input.normalizers.image import ImageNormalizer
from app.input.normalizers.sms import SMSNormalizer
from app.input.normalizers.url import URLNormalizer
from app.input.normalizers.webpage import WebpageNormalizer
from app.input.uploader import UploadValidationError, validate_upload
from app.schemas.schemas import ArtifactType

FIXTURES = Path(__file__).parent / "fixtures"


# ── Email normalizer ──────────────────────────────────────────────────────────


def test_email_fixture_parsed_correctly() -> None:
    """sample.eml must produce exactly 2 URLs and 1 attachment."""
    raw = (FIXTURES / "sample.eml").read_text(encoding="utf-8")
    artifact = EmailNormalizer().normalize(raw)

    assert artifact.type == ArtifactType.EMAIL

    # Exactly 2 URLs
    assert len(artifact.extracted_urls) == 2, (
        f"Expected 2 URLs, got {len(artifact.extracted_urls)}: {artifact.extracted_urls}"
    )
    url_set = set(artifact.extracted_urls)
    assert any("reports.benign-example.com" in u for u in url_set)
    assert any("docs.benign-example.com" in u for u in url_set)

    # Exactly 1 attachment
    assert len(artifact.attachments) == 1, (
        f"Expected 1 attachment, got {len(artifact.attachments)}"
    )
    att = artifact.attachments[0]
    assert att.filename == "Q3_2026_Report.pdf"
    assert att.extension == ".pdf"
    assert not att.is_suspicious_extension
    assert att.size_bytes > 0
    assert len(att.sha256) == 64  # SHA-256 hex


def test_email_headers_captured() -> None:
    """From, Subject, and SPF headers must be in metadata."""
    raw = (FIXTURES / "sample.eml").read_text(encoding="utf-8")
    artifact = EmailNormalizer().normalize(raw)

    assert "sender@benign-example.com" in artifact.metadata["from"]
    assert "Quarterly Report" in artifact.metadata["subject"]
    assert artifact.metadata["spf_result"] != ""


def test_email_raw_content_is_text_body() -> None:
    """raw_content must contain the plain-text body."""
    raw = (FIXTURES / "sample.eml").read_text(encoding="utf-8")
    artifact = EmailNormalizer().normalize(raw)
    assert "quarterly report" in artifact.raw_content.lower()


def test_email_attachment_sha256_matches() -> None:
    """The attachment sha256 in AttachmentInfo must match the raw bytes stored in metadata."""
    raw = (FIXTURES / "sample.eml").read_text(encoding="utf-8")
    artifact = EmailNormalizer().normalize(raw)
    att = artifact.attachments[0]
    stored_bytes = artifact.metadata["attachment_bytes"].get(att.sha256, b"")
    assert len(stored_bytes) > 0
    assert hashlib.sha256(stored_bytes).hexdigest() == att.sha256


def test_email_exe_attachment_flagged() -> None:
    """An .exe attachment must be flagged as is_suspicious_extension=True."""
    eml = (
        "From: x@x.com\r\n"
        "To: y@y.com\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n"
        "--B\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Body\r\n"
        "--B\r\n"
        "Content-Type: application/octet-stream\r\n"
        'Content-Disposition: attachment; filename="virus.exe"\r\n\r\n'
        "MZ\x90\x00\r\n"
        "--B--\r\n"
    )
    artifact = EmailNormalizer().normalize(eml)
    assert any(a.is_suspicious_extension for a in artifact.attachments)


# ── URL normalizer ────────────────────────────────────────────────────────────


def test_url_canonical_lowercase_scheme_host() -> None:
    artifact = URLNormalizer().normalize("HTTP://EXAMPLE.COM/Path?Q=1")
    assert artifact.normalized_url is not None
    assert artifact.normalized_url.startswith("http://example.com")


def test_url_components_extracted() -> None:
    artifact = URLNormalizer().normalize("https://sub.example.co.uk/page?x=1")
    assert artifact.metadata["domain"] == "example"
    assert artifact.metadata["subdomain"] == "sub"
    assert artifact.metadata["tld"] == "co.uk"


def test_url_embedded_redirect_detected() -> None:
    """Open-redirect URLs must populate extracted_urls."""
    artifact = URLNormalizer().normalize(
        "https://evil.com/go?url=https://phishing.example.com"
    )
    assert any("phishing.example.com" in u for u in artifact.extracted_urls)


def test_url_ip_host_detected() -> None:
    artifact = URLNormalizer().normalize("http://192.168.1.1/admin")
    assert artifact.metadata["is_ip_host"] is True


def test_url_normal_host_not_ip() -> None:
    artifact = URLNormalizer().normalize("https://example.com")
    assert artifact.metadata["is_ip_host"] is False


# ── SMS normalizer ────────────────────────────────────────────────────────────


def test_sms_extracts_urls() -> None:
    text = "Your KYC is pending. Visit http://kyc-update.example.com now!"
    artifact = SMSNormalizer().normalize(text)
    assert "http://kyc-update.example.com" in artifact.extracted_urls


def test_sms_extracts_multiple_urls() -> None:
    text = "Go to http://a.example.com or https://b.example.com for info."
    artifact = SMSNormalizer().normalize(text)
    assert len(artifact.extracted_urls) == 2


def test_sms_phone_number_extracted() -> None:
    text = "Call us on +91-98765-43210 or reply STOP."
    artifact = SMSNormalizer().normalize(text)
    assert len(artifact.metadata["phone_numbers_found"]) >= 1


def test_sms_sender_id_in_metadata() -> None:
    artifact = SMSNormalizer().normalize("Hello!", sender_id="SBIBNK")
    assert artifact.metadata["sender_id"] == "SBIBNK"


# ── Webpage normalizer ────────────────────────────────────────────────────────


_SAMPLE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Login - SecureBank</title></head>
<body>
  <a href="https://link1.example.com">Link 1</a>
  <form action="https://evil.example.com/steal">
    <input type="password" name="pwd">
  </form>
  <script src="https://cdn.example.com/script.js"></script>
</body>
</html>
"""


def test_webpage_title_extracted() -> None:
    artifact = WebpageNormalizer().normalize(_SAMPLE_HTML, source_url="https://fake-bank.example.com")
    assert artifact.metadata["page_title"] == "Login - SecureBank"


def test_webpage_all_links_extracted() -> None:
    artifact = WebpageNormalizer().normalize(_SAMPLE_HTML)
    urls = set(artifact.extracted_urls)
    assert any("link1.example.com" in u for u in urls)
    assert any("evil.example.com" in u for u in urls)
    assert any("cdn.example.com" in u for u in urls)


def test_webpage_source_url_in_metadata() -> None:
    artifact = WebpageNormalizer().normalize(_SAMPLE_HTML, source_url="https://fake-bank.example.com")
    assert artifact.metadata["source_url"] == "https://fake-bank.example.com"


# ── Image normalizer ──────────────────────────────────────────────────────────


def _make_png(width: int = 10, height: int = 10) -> bytes:
    """Create a minimal valid PNG in memory."""
    from PIL import Image as _Image

    buf = io.BytesIO()
    img = _Image.new("RGB", (width, height), color=(255, 0, 0))
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_image_valid_png_normalised() -> None:
    data = _make_png()
    artifact = ImageNormalizer().normalize(data, filename="test.png", mime_type="image/png")
    assert artifact.type == ArtifactType.IMAGE
    assert artifact.sha256 is not None
    assert len(artifact.sha256) == 64
    assert artifact.detected_mime == "image/png"
    assert artifact.file_size_bytes == len(data)


def test_image_sha256_correct() -> None:
    data = _make_png()
    artifact = ImageNormalizer().normalize(data)
    assert artifact.sha256 == hashlib.sha256(data).hexdigest()


def test_image_too_large_rejected() -> None:
    # Create a fake oversized payload (just zeros, > 50 MB)
    big_data = b"\x00" * (51 * 1024 * 1024)
    artifact = ImageNormalizer().normalize(big_data)
    assert "parse_error" in artifact.metadata
    assert artifact.raw_bytes is None


# ── File normalizer ───────────────────────────────────────────────────────────


def test_file_sha256_computed() -> None:
    data = b"%PDF-1.4 fake pdf content"
    artifact = FileNormalizer().normalize(data, filename="report.pdf")
    assert artifact.sha256 == hashlib.sha256(data).hexdigest()


def test_file_detected_mime_pdf() -> None:
    data = b"%PDF-1.4 fake"
    artifact = FileNormalizer().normalize(data, filename="report.pdf")
    assert artifact.detected_mime == "application/pdf"


def test_file_suspicious_extension_flagged() -> None:
    data = b"MZ\x90\x00fake exe"
    artifact = FileNormalizer().normalize(data, filename="malware.exe")
    assert artifact.attachments[0].is_suspicious_extension is True


def test_file_double_extension_detected() -> None:
    data = b"MZ\x90\x00fake"
    artifact = FileNormalizer().normalize(data, filename="invoice.pdf.exe")
    assert artifact.metadata["has_double_extension"] is True


# ── Upload hardening ──────────────────────────────────────────────────────────


def test_uploader_valid_pdf_passes() -> None:
    data = b"%PDF-1.4 " + b"x" * 100
    result = validate_upload(data, "report.pdf", "application/pdf", "file")
    assert result.filename.endswith(".pdf")
    assert result.size == len(data)


def test_uploader_oversized_raises() -> None:
    data = b"x" * (26 * 1024 * 1024)  # 26 MB > 25 MB email limit
    with pytest.raises(UploadValidationError, match="exceeds limit"):
        validate_upload(data, "big.eml", "message/rfc822", "email")


def test_uploader_blocked_extension_raises() -> None:
    with pytest.raises(UploadValidationError, match="extension"):
        validate_upload(b"data", "file.exe", "application/octet-stream", "file")


def test_uploader_blocked_mime_raises() -> None:
    with pytest.raises(UploadValidationError, match="MIME"):
        validate_upload(b"data", "file.php", "application/x-php", "file")


def test_uploader_exe_magic_bytes_blocked() -> None:
    """MZ magic bytes (PE executable) must be blocked even with .pdf extension."""
    exe_data = b"MZ\x90\x00" + b"\x00" * 100
    with pytest.raises(UploadValidationError, match="executable"):
        validate_upload(exe_data, "invoice.pdf", "application/pdf", "file")


def test_uploader_safe_random_filename_generated() -> None:
    data = b"%PDF-1.4 safe"
    result = validate_upload(data, "my secret report.pdf", "application/pdf", "file")
    assert "my secret report" not in result.filename
    assert result.original_filename == "my secret report.pdf"
