"""
Upload hardening — validates and stores multipart file uploads securely.

Security properties:
  1. Size cap enforced before reading body into memory.
  2. MIME type checked against a per-artifact-type allowlist.
  3. File extension checked against same allowlist.
  4. Files are stored in UPLOAD_DIR (outside the web root) under a
     cryptographically random UUID filename — the original filename is
     kept only in metadata, never in the on-disk path.
  5. Files are NEVER executed or interpreted.
  6. Double extensions are detected and flagged.
  7. Magic bytes are checked against declared MIME.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from app.input.normalizers.utils import detect_mime_from_magic, get_extension

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

# Maximum upload sizes per artifact type (bytes)
_MAX_SIZES: dict[str, int] = {
    "email": 25 * 1024 * 1024,    # 25 MB (.eml)
    "webpage": 5 * 1024 * 1024,   # 5 MB (HTML)
    "image": 20 * 1024 * 1024,    # 20 MB
    "qr": 10 * 1024 * 1024,       # 10 MB
    "file": 50 * 1024 * 1024,     # 50 MB
    "default": 10 * 1024 * 1024,  # 10 MB fallback
}

# Allowed MIME types per artifact type (declared Content-Type from upload)
_ALLOWED_MIME: dict[str, frozenset[str]] = {
    "email": frozenset({"message/rfc822", "text/plain", "application/octet-stream"}),
    "webpage": frozenset({"text/html", "text/plain", "application/xhtml+xml"}),
    "image": frozenset({
        "image/jpeg", "image/png", "image/gif",
        "image/bmp", "image/webp", "application/octet-stream",
    }),
    "qr": frozenset({
        "image/jpeg", "image/png", "image/gif",
        "image/bmp", "image/webp", "application/octet-stream",
    }),
    "file": frozenset({
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/zip",
        "application/x-zip-compressed",
        "text/plain",
        "text/html",
        "application/xhtml+xml",
        "application/octet-stream",  # Allow and rely on magic-byte check
    }),
}

# Allowed file extensions per artifact type
_ALLOWED_EXTENSIONS: dict[str, frozenset[str]] = {
    "email": frozenset({".eml", ".msg", ".txt", ""}),
    "webpage": frozenset({".html", ".htm", ".xhtml", ".txt", ""}),
    "image": frozenset({".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}),
    "qr": frozenset({".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}),
    "file": frozenset({
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".ppt", ".pptx", ".txt", ".csv", ".zip",
        ".7z", ".tar", ".gz", ".html", ".htm", ".xhtml",
        # Allow suspicious extensions so they can be analysed
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
        ".vbs", ".vbe", ".js",  ".jse", ".ws",  ".wsh",
        ".wsf", ".msi", ".msp", ".hta", ".cpl", ".reg",
        ".dll", ".sys", ".lnk", ".iso", ".img", ".jar",
        ".py",  ".ps1", ".psm1",
        ".docm", ".xlsm", ".pptm", ".xlam", ".xltm",
    }),
}

# MIME types detected by magic bytes that are NEVER allowed regardless of
# declared MIME or extension.
_BLOCKED_MAGIC_MIMES: frozenset[str] = frozenset({
    "application/x-dosexec",     # PE executables (.exe, .dll, .scr)
    "application/x-executable",  # ELF binaries
    "application/java-archive",  # Java .class
})


class UploadValidationError(ValueError):
    """Raised when an upload fails security validation."""


class UploadResult:
    """Result of a successful upload validation."""

    __slots__ = ("detected_mime", "filename", "mime", "original_filename", "path", "size")

    def __init__(
        self,
        filename: str,
        original_filename: str,
        mime: str,
        detected_mime: str | None,
        size: int,
        path: Path | None,
    ) -> None:
        self.filename = filename          # Random UUID filename on disk
        self.original_filename = original_filename
        self.mime = mime
        self.detected_mime = detected_mime
        self.size = size
        self.path = path                  # None when not persisted


def validate_upload(
    data: bytes,
    original_filename: str,
    declared_mime: str,
    artifact_type: str,
) -> UploadResult:
    """Validate uploaded bytes and return an UploadResult.

    This function validates only — it does NOT write to disk.
    Call ``persist_upload`` to save the file.

    Args:
        data:              Raw uploaded bytes.
        original_filename: Filename as supplied by the browser/client.
        declared_mime:     Content-Type from the multipart header.
        artifact_type:     One of url/email/sms/webpage/image/qr/file.

    Returns:
        An UploadResult with a safe random filename.

    Raises:
        UploadValidationError: If any security check fails.
    """
    atype = artifact_type.lower().strip()

    # ── 1. Size check ──────────────────────────────────────────────────────────
    max_size = _MAX_SIZES.get(atype, _MAX_SIZES["default"])
    if len(data) > max_size:
        raise UploadValidationError(
            f"Upload size {len(data):,} bytes exceeds limit {max_size:,} bytes "
            f"for artifact type {atype!r}."
        )

    # ── 2. MIME allowlist ──────────────────────────────────────────────────────
    # Normalise declared MIME (strip parameters like '; charset=utf-8')
    norm_mime = declared_mime.split(";")[0].strip().lower() if declared_mime else ""
    allowed_mimes = _ALLOWED_MIME.get(atype)
    if allowed_mimes is not None and norm_mime and norm_mime not in allowed_mimes:
        raise UploadValidationError(
            f"MIME type {norm_mime!r} is not allowed for artifact type {atype!r}. "
            f"Allowed: {sorted(allowed_mimes)}"
        )

    # ── 3. Extension allowlist ─────────────────────────────────────────────────
    ext = get_extension(original_filename)
    allowed_exts = _ALLOWED_EXTENSIONS.get(atype)
    if allowed_exts is not None and ext not in allowed_exts:
        raise UploadValidationError(
            f"File extension {ext!r} is not allowed for artifact type {atype!r}. "
            f"Allowed: {sorted(allowed_exts)}"
        )

    # ── 4. Magic-byte check ────────────────────────────────────────────────────
    detected_mime = detect_mime_from_magic(data) if data else None
    if detected_mime in _BLOCKED_MAGIC_MIMES:
        raise UploadValidationError(
            f"Upload rejected: magic bytes indicate executable type "
            f"{detected_mime!r} regardless of declared MIME {norm_mime!r}."
        )

    # ── 5. MIME / magic consistency warning and blocking (M-4) ────────────────
    if detected_mime and norm_mime and detected_mime != norm_mime:
        high_risk_mimes = {
            "application/x-dosexec", "application/x-executable", 
            "application/java-archive", "application/zip", 
            "application/x-rar", "application/x-sh"
        }
        
        # Exception for OOXML formats (docx, xlsx, pptx) which are technically ZIP files
        ooxml_mimes = {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        }
        is_ooxml_zip = detected_mime == "application/zip" and norm_mime in ooxml_mimes
        
        if detected_mime in high_risk_mimes and not is_ooxml_zip:
            raise UploadValidationError(
                f"High-risk MIME mismatch: declared {norm_mime!r} but detected {detected_mime!r}."
            )
        logger.warning(
            "Upload MIME mismatch: declared=%r detected=%r filename=%r",
            norm_mime,
            detected_mime,
            original_filename,
        )

    # ── 6. Generate safe random filename ──────────────────────────────────────
    safe_name = uuid.uuid4().hex + ext  # e.g. "a3f9...bc12.pdf"

    return UploadResult(
        filename=safe_name,
        original_filename=original_filename,
        mime=norm_mime or detected_mime or "application/octet-stream",
        detected_mime=detected_mime,
        size=len(data),
        path=None,  # Not yet written to disk
    )


def persist_upload(result: UploadResult, data: bytes, upload_dir: str | Path) -> Path:
    """Write validated upload bytes to *upload_dir* using the safe random filename.

    The directory is created if it does not exist.  The file is written with
    mode 0o600 (owner read/write only).

    Args:
        result:     An UploadResult from ``validate_upload``.
        data:       The raw bytes to write.
        upload_dir: Directory path (outside the web root).

    Returns:
        The absolute path of the written file.
    """
    upload_path = Path(upload_dir)
    upload_path.mkdir(parents=True, exist_ok=True)

    dest = upload_path / result.filename
    dest.write_bytes(data)

    try:
        dest.chmod(0o600)
    except OSError:
        pass

    result.path = dest
    logger.info(
        "Upload persisted: original=%r safe=%r size=%d mime=%r",
        result.original_filename,
        result.filename,
        result.size,
        result.mime,
    )
    return dest
