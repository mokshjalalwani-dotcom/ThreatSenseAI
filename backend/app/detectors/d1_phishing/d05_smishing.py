"""Detector 05 — Smishing (Domain 1: Phishing & Social Engineering)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class SmishingDetector(BaseDetector):
    """Detects SMS-based phishing: short-code/sender-ID patterns, shortened
    links, URL analysis, and NLP signals for urgency and credential_request.

    Stage implementation: Stage 5.
    """

    detector_id = "d05_smishing"
    name = "Smishing"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [ArtifactType.SMS]
    required_engines = ["nlp", "url"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run smishing detection (stub)."""
        return self._not_implemented(artifact)
