"""
Rules backend — Stage 4 stub.

The full implementation (versioned lexicon/regex YAML files, Hinglish support,
Indian scam patterns, negation handling) is built in Stage 4.  This stub
returns zero scores so the system works end-to-end in Stage 1.
"""

from __future__ import annotations

import logging

from app.engines.nlp.backends.base import SignalBackend
from app.schemas.schemas import NLPSignals

logger = logging.getLogger(__name__)


class RulesBackend(SignalBackend):
    """Deterministic lexicon/regex signal scorer.

    Stage 1: returns zeroed-out NLPSignals (stub).
    Stage 4: populated with full lexicons.
    """

    @property
    def backend_name(self) -> str:
        return "rules"

    async def analyze(self, text: str) -> NLPSignals:
        """Return zeroed NLPSignals (stub — will be implemented in Stage 4)."""
        logger.debug("RulesBackend.analyze called (stub — returning zeros)")
        return NLPSignals(
            backend_used=self.backend_name,
            text_length=len(text),
        )
