"""
FinetunedBackend — stub for Stage 13 DeBERTa fine-tuned model.

This backend is a STUB until Stage 13 is explicitly started.
It falls back to RulesBackend for all calls.
"""

from __future__ import annotations

import logging

from app.engines.nlp.backends.base import SignalBackend
from app.engines.nlp.backends.rules import RulesBackend
from app.schemas.schemas import NLPSignals

logger = logging.getLogger(__name__)


class FinetunedBackend(SignalBackend):
    """Stub backend — falls back to rules until Stage 13 fine-tuned model lands."""

    @property
    def backend_name(self) -> str:
        return "finetuned"

    async def analyze(self, text: str) -> NLPSignals:
        logger.debug("FinetunedBackend is a stub — delegating to RulesBackend")
        signals = await RulesBackend().analyze(text)
        return signals.model_copy(update={"backend_used": "finetuned_stub"})
