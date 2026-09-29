"""
Media Engine — Stage 8 full implementation.

QR decoding (pyzbar) + OCR (pytesseract) with graceful fallback.

Processing pipeline:
  1. QR decode: try pyzbar; fallback empty list.
  2. OCR: try pytesseract after grayscale + threshold preprocessing.
  3. All decoded strings go back through the URL normalizer.

Both operations are blocking — they run in an asyncio thread-pool executor.
"""

from __future__ import annotations

import asyncio
import logging

from app.schemas.schemas import Artifact

logger = logging.getLogger(__name__)


def _decode_qr_sync(image_bytes: bytes) -> list[str]:
    """Synchronous QR decoding via pyzbar."""
    try:
        import io

        from PIL import Image  # type: ignore[import]
        from pyzbar.pyzbar import decode  # type: ignore[import]

        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        results = decode(img)
        return [r.data.decode("utf-8", errors="replace") for r in results]
    except ImportError:
        logger.debug("pyzbar/Pillow not installed — QR decode skipped")
        return []
    except Exception as exc:
        logger.warning("QR decode error: %s", exc)
        return []


def _ocr_sync(image_bytes: bytes) -> str:
    """Synchronous OCR via pytesseract with grayscale preprocessing."""
    try:
        import io

        import pytesseract  # type: ignore[import]
        from PIL import Image  # type: ignore[import]

        img = Image.open(io.BytesIO(image_bytes)).convert("L")   # grayscale
        # Simple threshold to improve OCR on low-contrast images
        img = img.point(lambda x: 255 if x > 128 else 0, "1")
        img = img.convert("RGB")
        text = pytesseract.image_to_string(img, timeout=10)
        return text.strip()
    except ImportError:
        logger.debug("pytesseract/Pillow not installed — OCR skipped")
        return ""
    except Exception as exc:
        logger.warning("OCR error: %s", exc)
        return ""


class MediaEngine:
    """QR decoding + OCR engine for image and QR-code artifacts."""

    async def decode_qr(self, artifact: Artifact) -> list[str]:
        """Decode QR payloads from image bytes.

        Returns:
            List of decoded payload strings (URLs, text, etc.).
        """
        if not artifact.raw_bytes:
            return []
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _decode_qr_sync, artifact.raw_bytes)

    async def extract_text_ocr(self, artifact: Artifact) -> str:
        """Extract visible text from an image via OCR.

        Returns:
            Extracted text (may be empty string if OCR fails or no text found).
        """
        if not artifact.raw_bytes:
            return ""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _ocr_sync, artifact.raw_bytes)
