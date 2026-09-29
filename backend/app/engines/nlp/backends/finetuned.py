"""
Fine-tuned DeBERTa backend — STUB ONLY until Stage 13.

This module defines the interface, expected artifact path, and config keys
for the fine-tuned model so that:
  1. Selecting NLP_BACKEND=finetuned raises a clear, non-crashing error
     message from the API (never a silent failure or ImportError).
  2. Detectors that import NLPEngine never import this module directly.
  3. When Stage 13 trains the model, only THIS module changes; detector
     code stays identical.

Interface contract (for Stage 13)
----------------------------------
Input : str (raw UTF-8 text, any length — chunking is handled internally)
Output: NLPSignals (identical schema; backend_used="finetuned")

Expected artifact location
--------------------------
    ml/artifacts/nlp_model/
        model/                     ← HuggingFace model directory
        config.json
        tokenizer/
        REPORT.md
        model_card.md

Config keys (all optional — reasonable defaults apply)
------------------------------------------------------
    NLP_FINETUNED_MODEL_PATH   = ml/artifacts/nlp_model/model
    NLP_FINETUNED_MAX_LENGTH   = 512
    NLP_FINETUNED_BATCH_SIZE   = 8
    NLP_FINETUNED_DEVICE       = auto   (auto | cpu | cuda | mps)

See docs/NLP_FINETUNE_PLAN.md for the full Stage 13 specification.
"""

from __future__ import annotations

from app.engines.nlp.backends.base import SignalBackend
from app.schemas.schemas import NLPSignals

_NOT_TRAINED_MSG = (
    "NLP_BACKEND=finetuned is not available yet. "
    "The DeBERTa fine-tuned model will be implemented in Stage 13. "
    "Switch to NLP_BACKEND=rules (default), zeroshot, or ensemble."
)


class FinetunedBackend(SignalBackend):
    """Stub for the Stage-13 fine-tuned DeBERTa backend.

    Raises a clear RuntimeError on every call so that developers who
    accidentally select this backend get an actionable error instead of a
    silent zero or a cryptic ImportError.
    """

    @property
    def backend_name(self) -> str:
        return "finetuned"

    async def analyze(self, text: str) -> NLPSignals:
        """Raise NotImplementedError — model not yet trained.

        Raises:
            NotImplementedError: Always, until Stage 13 is complete.
        """
        raise NotImplementedError(_NOT_TRAINED_MSG)
