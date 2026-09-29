"""Detector 18 — Business Email Compromise (Domain 4: Email & Communication Security)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class BECDetector(BaseDetector):
    """Detects Business Email Compromise: executive/vendor display-name impersonation,
    payment/bank-detail-change/gift-card/wire language via NLP financial_intent +
    payment_request + authority, urgency + secrecy phrases ('don't tell anyone'),
    header authentication failures, reply-to divergence. Accepts optional
    ``known_contacts`` config for improved impersonation detection.

    Stage implementation: Stage 7.
    """

    detector_id = "d18_bec"
    name = "Business Email Compromise"
    domain = "Email & Communication Security"
    domain_id = "d4"
    accepted_artifact_types = [ArtifactType.EMAIL]
    required_engines = ["email", "nlp", "intel"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run BEC detection (stub)."""
        return self._not_implemented(artifact)
