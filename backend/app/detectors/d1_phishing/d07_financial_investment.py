"""Detector 07 — Financial & Investment Scams (Domain 1)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.detectors.d1_phishing._nlp_helpers import (
    build_evidence,
    nlp_verdict,
    score_from_signals,
)
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class FinancialInvestmentDetector(BaseDetector):
    """Detects financial & investment fraud: Ponzi, crypto scams, high-return fraud."""

    detector_id = "d07_financial_investment"
    name = "Financial & Investment Scam"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [ArtifactType.EMAIL, ArtifactType.SMS, ArtifactType.URL, ArtifactType.WEBPAGE]
    required_engines = ["nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        nlp = await ctx.get_nlp_signals()
        sw = {
            "investment_context": (nlp.investment_context, 0.35),
            "financial_intent":   (nlp.financial_intent,   0.25),
            "reward_scarcity":    (nlp.reward_scarcity,    0.20),
            "scam_intent":        (nlp.scam_intent,        0.10),
            "manipulation":       (nlp.manipulation,       0.10),
        }
        score = score_from_signals(sw)
        evidence = build_evidence(nlp, "nlp", sw)
        return self._result(artifact, score, nlp_verdict(score), evidence)
