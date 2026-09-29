"""Detector 05 — Smishing (SMS Phishing) (Domain 1)."""

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

# Smishing: SMS texts are short — URL presence is a strong signal
_SMISHING_URL_INDICATORS = {"bit.ly", "tinyurl", "goo.gl", "t.co", "is.gd", "rb.gy"}


@register_detector
class SmishingDetector(BaseDetector):
    """Detects smishing (SMS phishing): suspicious links + urgency + credential request."""

    detector_id = "d05_smishing"
    name = "Smishing (SMS Phishing)"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [ArtifactType.SMS]
    required_engines = ["nlp", "url"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        nlp = await ctx.get_nlp_signals()

        # SMS-specific: shortener/suspicious URL adds boost
        url_boost = 0.0
        if artifact.extracted_urls:
            url_boost += 0.10
            if any(s in url for url in artifact.extracted_urls for s in _SMISHING_URL_INDICATORS):
                url_boost += 0.15

        sw = {
            "phishing_intent":    (nlp.phishing_intent,    0.30),
            "credential_request": (nlp.credential_request, 0.25),
            "urgency":            (nlp.urgency,            0.20),
            "payment_request":    (nlp.payment_request,    0.10),
        }
        score = min(1.0, score_from_signals(sw) + url_boost)
        evidence = build_evidence(nlp, "nlp", sw)
        return self._result(artifact, score, nlp_verdict(score), evidence)
