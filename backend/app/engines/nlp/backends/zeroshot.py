"""
Zero-shot backend — Stage 4 stub.

The full implementation (pretrained NLI checkpoint from Hugging Face, batch
inference, long-text chunking, CPU-friendly, lazy model loading) is built in
Stage 4.  This stub returns zero scores.
"""

from __future__ import annotations

import logging

from app.engines.nlp.backends.base import SignalBackend
from app.schemas.schemas import NLPSignals

logger = logging.getLogger(__name__)


class ZeroShotBackend(SignalBackend):
    """Pretrained zero-shot/NLI signal scorer.

    Stage 1: stub — returns zeroed NLPSignals.
    Stage 4: uses a DeBERTa-v3 NLI checkpoint for hypothesis-based scoring.
    """

    @property
    def backend_name(self) -> str:
        return "zeroshot"

    async def analyze(self, text: str) -> NLPSignals:
        """Return zeroed NLPSignals (stub — will be implemented in Stage 4)."""
        logger.debug("ZeroShotBackend.analyze called (stub — returning zeros)")
        return NLPSignals(
            backend_used=self.backend_name,
            text_length=len(text),
        )
