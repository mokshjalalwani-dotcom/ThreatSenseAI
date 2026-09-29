"""Detector 04 — Scam / Fraud (Domain 1: Phishing & Social Engineering)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class ScamFraudDetector(BaseDetector):
    """Detects scam and fraud content: financial_intent, payment_request,
    reward/refund language, and malicious URLs.

    Stage implementation: Stage 5.
    """

    detector_id = "d04_scam_fraud"
    name = "Scam / Fraud"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [
        ArtifactType.EMAIL,
        ArtifactType.SMS,
        ArtifactType.URL,
        ArtifactType.WEBPAGE,
    ]
    required_engines = ["nlp", "url", "intel"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run scam/fraud detection (stub)."""
        return self._not_implemented(artifact)
