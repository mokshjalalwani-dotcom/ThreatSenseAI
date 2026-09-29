"""
Ensemble backend — Stage 4 stub.

The full implementation (configurable weights from YAML, combining rules +
zeroshot scores per signal) is built in Stage 4.  This stub delegates to
RulesBackend so the system starts correctly.
"""

from __future__ import annotations

import logging

from app.engines.nlp.backends.base import SignalBackend
from app.engines.nlp.backends.rules import RulesBackend
from app.schemas.schemas import NLPSignals

logger = logging.getLogger(__name__)


class EnsembleBackend(SignalBackend):
    """Weighted combination of rules + zeroshot backends.

    Stage 1: delegates to RulesBackend (stub).
    Stage 4: combines rules and zeroshot with YAML-configured weights.
    """

    def __init__(self) -> None:
        # Until Stage 4, the ensemble falls back to the rules backend
        self._fallback = RulesBackend()

    @property
    def backend_name(self) -> str:
        return "ensemble"

    async def analyze(self, text: str) -> NLPSignals:
        """Return ensemble signals (stub — delegates to rules in Stage 1)."""
        logger.debug(
            "EnsembleBackend.analyze called (stub — delegating to rules backend)"
        )
        signals = await self._fallback.analyze(text)
        # Override backend_used so callers know what actually ran
        return signals.model_copy(update={"backend_used": self.backend_name})
