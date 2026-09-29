"""Detector 03 — Spear Phishing (Domain 1: Phishing & Social Engineering)."""

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
class SpearPhishingDetector(BaseDetector):
    """Detects targeted spear phishing: personalisation + phishing + authority combo."""

    detector_id = "d03_spear_phishing"
    name = "Spear Phishing"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [ArtifactType.EMAIL, ArtifactType.SMS]
    required_engines = ["nlp", "intel"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        nlp = await ctx.get_nlp_signals()

        # Spear phishing = phishing intent + authority/personalisation signals
        personalisation_boost = 0.0
        meta = artifact.metadata
        if meta.get("recipient_name") and meta.get("recipient_org"):
            personalisation_boost = 0.15  # targeted content

        sw = {
            "phishing_intent":    (nlp.phishing_intent,    0.35),
            "authority":          (nlp.authority,           0.25),
            "credential_request": (nlp.credential_request, 0.20),
            "urgency":            (nlp.urgency,            0.10),
        }
        score = min(1.0, score_from_signals(sw) + personalisation_boost)
        evidence = build_evidence(nlp, "nlp", sw)
        return self._result(artifact, score, nlp_verdict(score), evidence)
