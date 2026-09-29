"""Detector 09 — Tech Support Scams (Domain 1)."""

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
class TechSupportScamDetector(BaseDetector):
    """Detects tech support scams: fake helplines, remote access requests."""

    detector_id = "d09_tech_support_scams"
    name = "Tech Support Scam"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [ArtifactType.EMAIL, ArtifactType.SMS, ArtifactType.URL, ArtifactType.WEBPAGE]
    required_engines = ["nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        nlp = await ctx.get_nlp_signals()
        sw = {
            "tech_support_context":  (nlp.tech_support_context,  0.35),
            "remote_access_request": (nlp.remote_access_request, 0.30),
            "fear":                  (nlp.fear,                  0.15),
            "payment_request":       (nlp.payment_request,       0.10),
            "urgency":               (nlp.urgency,               0.10),
        }
        score = score_from_signals(sw)
        evidence = build_evidence(nlp, "nlp", sw)
        return self._result(artifact, score, nlp_verdict(score), evidence)
