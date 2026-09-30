"""Detector 08 — Recruitment Scams (Domain 1)."""

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
class RecruitmentScamDetector(BaseDetector):
    """Detects fake job/work-from-home recruitment scams."""

    detector_id = "d08_recruitment_scams"
    name = "Recruitment Scam"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [ArtifactType.EMAIL, ArtifactType.SMS, ArtifactType.WEBPAGE]
    required_engines = ["nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        nlp = await ctx.get_nlp_signals()
        sw = {
            "recruitment_context": (nlp.recruitment_context, 1.50),
            "reward_scarcity":     (nlp.reward_scarcity,     0.80),
            "financial_intent":    (nlp.financial_intent,    0.80),
            "manipulation":        (nlp.manipulation,        0.50),
            "payment_request":     (nlp.payment_request,     1.00),
        }
        score = score_from_signals(sw)
        evidence = build_evidence(nlp, "nlp", sw)
        return self._result(artifact, score, nlp_verdict(score), evidence)
