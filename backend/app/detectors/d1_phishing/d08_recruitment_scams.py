"""Detector 08 — Recruitment Scams (Domain 1: Phishing & Social Engineering)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class RecruitmentScamDetector(BaseDetector):
    """Detects recruitment scams: recruitment_context signal, unrealistic salary/offer,
    registration/training-fee requests, document/ID/bank-detail requests,
    free-mail HR addresses (gmail/yahoo HR), domain analysis.

    Stage implementation: Stage 5.
    """

    detector_id = "d08_recruitment_scams"
    name = "Recruitment Scams"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [ArtifactType.EMAIL, ArtifactType.SMS]
    required_engines = ["nlp", "url"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run recruitment scam detection (stub)."""
        return self._not_implemented(artifact)
