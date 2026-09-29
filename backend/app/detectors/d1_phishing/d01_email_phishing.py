"""Detector 01 — Email Phishing (Domain 1: Phishing & Social Engineering)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class EmailPhishingDetector(BaseDetector):
    """Detects phishing emails using NLP signals, URL analysis, brand impersonation,
    sender/reply-to mismatch, and threat-intel lookups.

    Stage implementation: Stage 5.
    """

    detector_id = "d01_email_phishing"
    name = "Email Phishing"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [ArtifactType.EMAIL]
    required_engines = ["nlp", "url", "intel"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run email phishing detection (stub)."""
        return self._not_implemented(artifact)
