"""Image input normalizer.

Validates image uploads using Pillow — checks format, dimensions, and
file size.  Computes SHA-256 and detects MIME from magic bytes.

Does NOT decode or OCR the image — that is the MediaEngine's job in Stage 8.
"""

from __future__ import annotations

import io
import logging

from app.input.normalizers.base import BaseNormalizer
from app.input.normalizers.utils import detect_mime_from_magic, sha256_hex
from app.schemas.schemas import Artifact, ArtifactType

logger = logging.getLogger(__name__)

# Maximum image dimensions (width x height) accepted
_MAX_WIDTH = 10_000
_MAX_HEIGHT = 10_000
_MAX_BYTES = 50 * 1024 * 1024  # 50 MB


class ImageNormalizer(BaseNormalizer):
    """Validates and normalises image bytes.

    Accepted MIME types: image/jpeg, image/png, image/gif, image/bmp, image/webp.
    """

    artifact_type = ArtifactType.IMAGE

    def normalize(self, raw: str | bytes, **kwargs: object) -> Artifact:
        filename: str = str(kwargs.get("filename", "upload.bin"))
        declared_mime: str = str(kwargs.get("mime_type", ""))

        if isinstance(raw, str):
            raw = raw.encode("latin-1", errors="replace")

        if len(raw) > _MAX_BYTES:
            return Artifact(
                type=ArtifactType.IMAGE,
                raw_bytes=None,
                metadata={
                    "filename": filename,
                    "parse_error": f"Image too large: {len(raw)} bytes > {_MAX_BYTES}",
                },
            )

        detected_mime = detect_mime_from_magic(raw)
        digest = sha256_hex(raw)

        # Validate with Pillow
        width: int | None = None
        height: int | None = None
        pil_format: str | None = None
        parse_error: str | None = None

        try:
            from PIL import Image, UnidentifiedImageError

            try:
                with Image.open(io.BytesIO(raw)) as img:
                    width, height = img.size
                    pil_format = img.format
                    if width > _MAX_WIDTH or height > _MAX_HEIGHT:
                        parse_error = (
                            f"Image dimensions {width}x{height} exceed limit "
                            f"{_MAX_WIDTH}x{_MAX_HEIGHT}"
                        )
            except UnidentifiedImageError as exc:
                parse_error = f"Pillow could not identify image: {exc}"
        except ImportError:
            logger.warning("Pillow not installed — skipping image validation")

        meta: dict = {
            "filename": filename,
            "declared_mime": declared_mime,
            "detected_mime": detected_mime,
            "sha256": digest,
            "size_bytes": len(raw),
            "width": width,
            "height": height,
            "pil_format": pil_format,
        }
        if parse_error:
            meta["parse_error"] = parse_error

        return Artifact(
            type=ArtifactType.IMAGE,
            raw_content="",
            raw_bytes=raw,
            sha256=digest,
            file_size_bytes=len(raw),
            detected_mime=detected_mime,
            metadata=meta,
        )
