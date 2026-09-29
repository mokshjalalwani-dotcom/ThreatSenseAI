"""Detector 04 — Scam & Fraud (Domain 1: Phishing & Social Engineering)."""

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
class ScamFraudDetector(BaseDetector):
    """Detects scam/fraud: advance-fee, lottery, too-good-to-be-true offers."""

    detector_id = "d04_scam_fraud"
    name = "Scam & Fraud"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [
        ArtifactType.EMAIL, ArtifactType.SMS, ArtifactType.URL, ArtifactType.WEBPAGE,
    ]
    required_engines = ["nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        nlp = await ctx.get_nlp_signals()
        sw = {
            "scam_intent":       (nlp.scam_intent,       0.35),
            "reward_scarcity":   (nlp.reward_scarcity,   0.25),
            "financial_intent":  (nlp.financial_intent,  0.20),
            "manipulation":      (nlp.manipulation,      0.10),
            "payment_request":   (nlp.payment_request,   0.10),
        }
        score = score_from_signals(sw)
        evidence = build_evidence(nlp, "nlp", sw)
        return self._result(artifact, score, nlp_verdict(score), evidence)
