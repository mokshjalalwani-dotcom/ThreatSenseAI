"""
ZeroShotBackend — optional zero-shot NLI signal scorer.

Uses facebook/bart-large-mnli via HuggingFace Transformers when available.
Falls back to RulesBackend when the model is not installed or
NLP_ZEROSHOT=false is set.

Label mapping:
  Each NLPSignals field maps to one or more NLI hypothesis strings.
  The entailment probability becomes the signal score.

Performance:
  First call loads the model (~500 MB, ~5 s on CPU).
  Subsequent calls use the cached pipeline.
  Text is truncated to 512 tokens before inference.
  Async: runs model in a thread pool to avoid blocking the event loop.
"""

from __future__ import annotations

import asyncio
import logging
import os
from functools import lru_cache
from typing import Any

from app.engines.nlp.backends.base import SignalBackend
from app.engines.nlp.backends.rules import RulesBackend
from app.schemas.schemas import NLPSignals

logger = logging.getLogger(__name__)

# HuggingFace model identifier
_MODEL_ID = "facebook/bart-large-mnli"
_MAX_LENGTH = 512  # tokens

# Hypothesis templates for each NLPSignals field
_HYPOTHESES: dict[str, str] = {
    "urgency":              "This message creates a sense of urgency or deadline.",
    "fear":                 "This message tries to create fear or panic in the reader.",
    "authority":            "This message claims to be from an authority or official body.",
    "reward_scarcity":      "This message offers a reward, prize, or limited-time benefit.",
    "financial_intent":     "This message is requesting a financial transaction or payment.",
    "credential_request":   "This message asks for passwords, OTPs, or personal credentials.",
    "manipulation":         "This message uses psychological manipulation or social engineering.",
    "phishing_intent":      "This message is a phishing attempt trying to steal information.",
    "scam_intent":          "This message is a scam designed to defraud the recipient.",
    "investment_context":   "This message promotes an investment opportunity.",
    "recruitment_context":  "This message is a job recruitment or work-from-home offer.",
    "tech_support_context": "This message claims to offer technical support.",
    "government_service_claim": "This message claims to be from a government agency.",
    "payment_request":      "This message is requesting a payment be made immediately.",
    "remote_access_request": "This message is asking the recipient to install remote access software.",
}


@lru_cache(maxsize=1)
def _load_pipeline() -> Any | None:
    """Lazy-load the zero-shot classification pipeline (cached after first call)."""
    if os.getenv("NLP_ZEROSHOT", "false").lower() != "true":
        logger.info("ZeroShotBackend: NLP_ZEROSHOT!=true — using rules fallback")
        return None
    try:
        from transformers import pipeline  # type: ignore[import]
        logger.info("Loading zero-shot pipeline: %s", _MODEL_ID)
        pipe = pipeline(
            "zero-shot-classification",
            model=_MODEL_ID,
            device=-1,         # CPU; set CUDA_VISIBLE_DEVICES for GPU
            multi_label=True,
        )
        logger.info("Zero-shot pipeline loaded.")
        return pipe
    except Exception as exc:
        logger.warning("ZeroShotBackend load failed (%s) — falling back to rules", exc)
        return None


class ZeroShotBackend(SignalBackend):
    """Zero-shot NLI signal scorer using BART-large-MNLI.

    Falls back to RulesBackend when the model is unavailable.
    """

    @property
    def backend_name(self) -> str:
        return "zeroshot"

    async def analyze(self, text: str) -> NLPSignals:
        pipe = _load_pipeline()
        if pipe is None:
            return await RulesBackend().analyze(text)

        # Run blocking model inference in a thread pool
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, self._run_inference, pipe, text)
        return result

    def _run_inference(self, pipe: Any, text: str) -> NLPSignals:
        truncated = text[:_MAX_LENGTH * 4]  # rough char cutoff before tokenisation
        labels = list(_HYPOTHESES.values())

        try:
            output = pipe(truncated, candidate_labels=labels, multi_label=True)
            score_map = dict(zip(output["labels"], output["scores"], strict=False))
        except Exception as exc:
            logger.warning("Zero-shot inference error: %s — returning empty signals", exc)
            return NLPSignals(backend_used="zeroshot_failed", text_length=len(text))

        def _get(key: str) -> float:
            hyp = _HYPOTHESES[key]
            return round(float(score_map.get(hyp, 0.0)), 4)

        return NLPSignals(
            urgency=_get("urgency"),
            fear=_get("fear"),
            authority=_get("authority"),
            reward_scarcity=_get("reward_scarcity"),
            financial_intent=_get("financial_intent"),
            credential_request=_get("credential_request"),
            manipulation=_get("manipulation"),
            phishing_intent=_get("phishing_intent"),
            scam_intent=_get("scam_intent"),
            investment_context=_get("investment_context"),
            recruitment_context=_get("recruitment_context"),
            tech_support_context=_get("tech_support_context"),
            government_service_claim=_get("government_service_claim"),
            payment_request=_get("payment_request"),
            remote_access_request=_get("remote_access_request"),
            backend_used="zeroshot",
            text_length=len(text),
        )
