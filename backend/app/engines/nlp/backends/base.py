"""
SignalBackend — abstract base class for all NLP signal backends.

Every backend must implement ``analyze(text) -> NLPSignals`` and expose a
``backend_name`` property.  Detectors depend ONLY on NLPEngine (which wraps a
backend); they never import a backend directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.schemas.schemas import NLPSignals


class SignalBackend(ABC):
    """Abstract NLP signal backend.

    Implementations:
      - ``RulesBackend``     — deterministic lexicon/regex (Stage 4)
      - ``ZeroShotBackend``  — pretrained NLI model (Stage 4)
      - ``FinetunedBackend`` — fine-tuned DeBERTa (Stage 13, stub until then)
      - ``EnsembleBackend``  — configurable combination (Stage 4)
    """

    @abstractmethod
    async def analyze(self, text: str) -> NLPSignals:
        """Score all signals for *text*.

        Args:
            text: The raw UTF-8 text to analyse (any length).

        Returns:
            A fully-populated NLPSignals object.  Scores default to 0.0 when
            the backend cannot determine a value.
        """

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Short identifier matching NLPBackend enum values."""
