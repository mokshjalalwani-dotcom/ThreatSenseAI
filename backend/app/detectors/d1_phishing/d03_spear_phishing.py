"""Detector 03 — Spear Phishing (Domain 1: Phishing & Social Engineering)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class SpearPhishingDetector(BaseDetector):
    """Detects targeted spear-phishing: personalisation cues (recipient name/role/org
    mentions), internal-sounding context, specific project/person references, sender
    identity plausibility. Accepts optional ``recipient_profile`` metadata.

    Stage implementation: Stage 5.
    """

    detector_id = "d03_spear_phishing"
    name = "Spear Phishing"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [ArtifactType.EMAIL]
    required_engines = ["nlp", "url"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run spear phishing detection (stub)."""
        return self._not_implemented(artifact)
