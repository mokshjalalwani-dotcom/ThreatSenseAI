"""Detector 09 — Technical Support Scams (Domain 1: Phishing & Social Engineering)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class TechSupportScamDetector(BaseDetector):
    """Detects tech-support scams: tech_support_context signal, fake virus/locked-account
    warnings, support phone numbers, remote-access tool names (AnyDesk, TeamViewer,
    UltraViewer), remote_access_request and payment_request signals.

    Stage implementation: Stage 5.
    """

    detector_id = "d09_tech_support_scams"
    name = "Technical Support Scams"
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
        """Run tech support scam detection (stub)."""
        return self._not_implemented(artifact)
