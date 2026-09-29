"""Detector 06 — Government / Service Scams (Domain 1: Phishing & Social Engineering)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class GovernmentServiceScamDetector(BaseDetector):
    """Detects government/service impersonation scams: government_service_claim signal,
    claimed_org extraction, domain/sender authenticity against a verified YAML list
    of .gov.in / .nic.in domains, KYC/refund/penalty/digital-arrest language.

    Stage implementation: Stage 5.
    """

    detector_id = "d06_government_scams"
    name = "Government / Service Scams"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [
        ArtifactType.EMAIL,
        ArtifactType.SMS,
        ArtifactType.URL,
        ArtifactType.WEBPAGE,
    ]
    required_engines = ["nlp", "url"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run government/service scam detection (stub)."""
        return self._not_implemented(artifact)
