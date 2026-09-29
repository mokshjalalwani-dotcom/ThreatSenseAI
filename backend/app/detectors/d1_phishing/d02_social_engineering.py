"""Detector 02 — Social Engineering (Domain 1: Phishing & Social Engineering)."""

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
class SocialEngineeringDetector(BaseDetector):
    """Detects social engineering attacks: manipulation, authority claims, fear tactics."""

    detector_id = "d02_social_engineering"
    name = "Social Engineering"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [ArtifactType.EMAIL, ArtifactType.SMS, ArtifactType.URL, ArtifactType.WEBPAGE]
    required_engines = ["nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        nlp = await ctx.get_nlp_signals()
        sw = {
            "manipulation":   (nlp.manipulation,   0.35),
            "authority":      (nlp.authority,       0.25),
            "fear":           (nlp.fear,            0.20),
            "urgency":        (nlp.urgency,         0.15),
            "reward_scarcity":(nlp.reward_scarcity, 0.05),
        }
        score = score_from_signals(sw)
        evidence = build_evidence(nlp, "nlp", sw)
        return self._result(artifact, score, nlp_verdict(score), evidence)
