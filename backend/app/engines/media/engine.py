"""
Media Engine — stub for Stage 8.

Full implementation: image validation/sanitisation (strip EXIF, re-encode),
QR decoding (pyzbar with OpenCV fallback), OCR (Tesseract primary, swappable),
preprocessing (grayscale, threshold, deskew), fuzzy URL repair from OCR errors.
"""

from __future__ import annotations

import logging

from app.schemas.schemas import Artifact

logger = logging.getLogger(__name__)


class MediaEngine:
    """Shared QR decoding and OCR engine.

    Stage 1: stub.
    Stage 8: full QR + OCR + image preprocessing pipeline.
    """

    async def decode_qr(self, artifact: Artifact) -> list[str]:
        """Decode QR payloads from an image artifact.

        Args:
            artifact: An IMAGE or QR artifact with raw_bytes.

        Returns:
            List of decoded payload strings (may be empty if no QR found).
        """
        logger.debug("MediaEngine.decode_qr called (stub)")
        return []

    async def extract_text_ocr(self, artifact: Artifact) -> str:
        """Extract text from an image via OCR.

        Args:
            artifact: An IMAGE artifact with raw_bytes.

        Returns:
            Extracted text string (may be empty).
        """
        logger.debug("MediaEngine.extract_text_ocr called (stub)")
        return ""
