"""
NLPEngine — thin wrapper around a pluggable SignalBackend.

Detectors call ``NLPEngine.analyze(text)`` and never import a backend
directly, so swapping the backend (rules → zeroshot → finetuned) requires
zero detector code changes.
"""

from __future__ import annotations

import logging

from app.engines.nlp.backends.base import SignalBackend
from app.schemas.schemas import NLPSignals

logger = logging.getLogger(__name__)


class NLPEngine:
    """Shared NLP engine used by all Domain-1 and related detectors.

    Args:
        backend: A concrete SignalBackend implementation.
    """

    def __init__(self, backend: SignalBackend) -> None:
        self._backend = backend
        logger.info("NLPEngine initialised with backend=%r", backend.backend_name)

    async def analyze(self, text: str) -> NLPSignals:
        """Run the backend and return NLPSignals.

        Args:
            text: Raw UTF-8 text (any length).

        Returns:
            NLPSignals with all fields populated by the backend.
        """
        return await self._backend.analyze(text)

    @property
    def backend_name(self) -> str:
        """The active backend identifier (rules / zeroshot / finetuned / ensemble)."""
        return self._backend.backend_name


def build_nlp_engine(backend_name: str) -> NLPEngine:
    """Factory: create an NLPEngine from a backend name string.

    Args:
        backend_name: One of 'rules', 'zeroshot', 'finetuned', 'ensemble'.

    Returns:
        An NLPEngine wrapping the requested backend.

    Raises:
        ValueError: If backend_name is not recognised.
    """
    from app.engines.nlp.backends import (
        EnsembleBackend,
        FinetunedBackend,
        RulesBackend,
        ZeroShotBackend,
    )

    backends: dict[str, type[SignalBackend]] = {
        "rules": RulesBackend,
        "zeroshot": ZeroShotBackend,
        "finetuned": FinetunedBackend,
        "ensemble": EnsembleBackend,
    }

    cls = backends.get(backend_name.lower())
    if cls is None:
        raise ValueError(
            f"Unknown NLP backend {backend_name!r}. "
            f"Valid options: {list(backends.keys())}"
        )

    return NLPEngine(backend=cls())
