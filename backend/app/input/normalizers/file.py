"""Arbitrary file input normalizer.

Handles static file uploads: computes SHA-256, detects MIME from magic bytes,
checks for double extensions, and flags suspicious file types.

The file is NEVER executed.  Only static metadata is extracted here.
Deep static analysis (YARA, macro detection, PDF JS) happens in Stage 7.
"""

from __future__ import annotations

import logging
from pathlib import PurePosixPath

from app.input.normalizers.base import BaseNormalizer
from app.input.normalizers.utils import (
    detect_mime_from_magic,
    get_extension,
    is_suspicious_extension,
    sha256_hex,
)
from app.schemas.schemas import Artifact, ArtifactType, AttachmentInfo

logger = logging.getLogger(__name__)

_MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MB hard cap


class FileNormalizer(BaseNormalizer):
    """Normalizer for arbitrary binary file uploads."""

    artifact_type = ArtifactType.FILE

    def normalize(self, raw: str | bytes, **kwargs: object) -> Artifact:
        filename: str = str(kwargs.get("filename", "upload.bin"))
        declared_mime: str = str(kwargs.get("mime_type", ""))

        if isinstance(raw, str):
            raw = raw.encode("latin-1", errors="replace")

        # Size guard
        if len(raw) > _MAX_FILE_BYTES:
            return Artifact(
                type=ArtifactType.FILE,
                raw_bytes=None,
                metadata={
                    "filename": filename,
                    "parse_error": f"File too large: {len(raw)} > {_MAX_FILE_BYTES} bytes",
                },
            )

        digest = sha256_hex(raw)
        detected_mime = detect_mime_from_magic(raw)
        ext = get_extension(filename)
        suspicious = is_suspicious_extension(filename)

        # Double-extension check (e.g. "invoice.pdf.exe")
        # PurePosixPath suffixes gives all extensions
        all_suffixes = [s.lower() for s in PurePosixPath(filename).suffixes]
        has_double_extension = len(all_suffixes) >= 2

        attachment = AttachmentInfo(
            filename=filename,
            declared_mime=declared_mime,
            detected_mime=detected_mime,
            extension=ext,
            size_bytes=len(raw),
            sha256=digest,
            is_suspicious_extension=suspicious,
        )

        return Artifact(
            type=ArtifactType.FILE,
            raw_content="",
            raw_bytes=raw,
            sha256=digest,
            file_size_bytes=len(raw),
            detected_mime=detected_mime,
            attachments=[attachment],
            metadata={
                "filename": filename,
                "declared_mime": declared_mime,
                "detected_mime": detected_mime,
                "extension": ext,
                "all_suffixes": all_suffixes,
                "has_double_extension": has_double_extension,
                "is_suspicious_extension": suspicious,
                "size_bytes": len(raw),
                "sha256": digest,
            },
        )
