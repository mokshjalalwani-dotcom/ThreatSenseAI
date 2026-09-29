"""Detector 02 — Social Engineering (Domain 1: Phishing & Social Engineering)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class SocialEngineeringDetector(BaseDetector):
    """Detects social engineering content: urgency, fear, authority, reward/scarcity,
    and manipulation NLP signals across emails, SMS, URLs, and webpages.

    Stage implementation: Stage 5.
    """

    detector_id = "d02_social_engineering"
    name = "Social Engineering"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [
        ArtifactType.EMAIL,
        ArtifactType.SMS,
        ArtifactType.WEBPAGE,
        ArtifactType.URL,
    ]
    required_engines = ["nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run social engineering detection (stub)."""
        return self._not_implemented(artifact)
