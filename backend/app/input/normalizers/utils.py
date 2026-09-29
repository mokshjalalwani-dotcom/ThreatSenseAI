"""
Shared utilities for all input normalizers.

URL extraction, magic-byte detection, SHA-256 hashing, phone number
extraction, and suspicious extension checking live here so every normalizer
can reuse them without duplication.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath

# ── URL extraction ─────────────────────────────────────────────────────────────

# Matches http:// and https:// URLs in text; deliberately conservative to
# avoid false positives in code or data fields.
_URL_RE = re.compile(
    r"""https?://                        # scheme
        (?:[A-Za-z0-9\-._~:@!$&'()*+,;=/?#\[\]%]+)  # authority + path
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Phone number patterns (simplified; E.164 + Indian mobile patterns)
_PHONE_RE = re.compile(
    r"""(?:
        \+?[0-9]{1,3}[\s\-.]?    # country code
    )?
    (?:\([0-9]{1,4}\)[\s\-.]?)?  # area code in parens
    [0-9]{4,6}                   # subscriber number part 1
    [\s\-.]?
    [0-9]{4,6}                   # subscriber number part 2
    """,
    re.VERBOSE,
)


def extract_urls(text: str) -> list[str]:
    """Extract all http/https URLs from *text*, deduplicated in order.

    Args:
        text: Any UTF-8 string.

    Returns:
        Ordered list of unique URLs found.
    """
    seen: set[str] = set()
    result: list[str] = []
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(").,;>'\"")  # Strip common trailing punctuation
        if url not in seen:
            seen.add(url)
            result.append(url)
    return result


def extract_phone_numbers(text: str) -> list[str]:
    """Extract phone-number-like patterns from *text*.

    This is intentionally broad (catches most patterns) rather than strict
    (E.164 validated) — false negatives are worse than false positives for
    threat detection.

    Args:
        text: Any UTF-8 string.

    Returns:
        List of raw phone number strings found.
    """
    return [m.group(0).strip() for m in _PHONE_RE.finditer(text) if len(m.group(0).strip()) >= 7]


# ── Magic-byte (MIME) detection ───────────────────────────────────────────────

_MAGIC: list[tuple[bytes, str]] = [
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"BM", "image/bmp"),
    (b"RIFF", "image/webp"),           # WebP is RIFF container
    (b"%PDF", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"PK\x05\x06", "application/zip"),
    (b"PK\x07\x08", "application/zip"),
    (b"\xd0\xcf\x11\xe0", "application/msword"),        # OLE2 (doc/xls/ppt)
    (b"\x50\x4b\x03\x04", "application/zip"),           # OOXML (docx/xlsx)
    (b"Rar!\x1a\x07", "application/x-rar-compressed"),
    (b"\x7fELF", "application/x-executable"),
    (b"MZ", "application/x-dosexec"),                   # PE (exe/dll/scr)
    (b"\xca\xfe\xba\xbe", "application/java-archive"),  # Java class
    (b"\x4d\x5a", "application/x-dosexec"),             # Alternative PE
]


def detect_mime_from_magic(data: bytes) -> str | None:
    """Detect MIME type from the first bytes of *data*.

    Args:
        data: The raw file content (any length; only the first 16 bytes matter).

    Returns:
        MIME type string if recognised, else None.
    """
    for magic, mime in _MAGIC:
        if data[: len(magic)] == magic:
            return mime
    return None


# ── SHA-256 hashing ───────────────────────────────────────────────────────────


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()


# ── Suspicious extension list ─────────────────────────────────────────────────

# Extensions that are executable or macro-capable and therefore suspicious
# when seen in email attachments or file uploads.
_SUSPICIOUS_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
        ".vbs", ".vbe", ".js",  ".jse", ".ws",  ".wsh",
        ".wsf", ".msi", ".msp", ".hta", ".cpl", ".reg",
        ".dll", ".sys", ".lnk", ".iso", ".img", ".jar",
        ".py",  ".ps1", ".psm1",
        # Macro-enabled Office
        ".docm", ".xlsm", ".pptm", ".xlam", ".xltm",
    }
)


def is_suspicious_extension(filename: str) -> bool:
    """Return True if *filename*'s extension is in the suspicious set."""
    suffix = PurePosixPath(filename).suffix.lower()
    return suffix in _SUSPICIOUS_EXTENSIONS


def get_extension(filename: str) -> str:
    """Return the lowercase file extension including the dot, or ''."""
    return PurePosixPath(filename).suffix.lower()
