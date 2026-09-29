"""Detector 07 — Financial / Investment Scams (Domain 1: Phishing & Social Engineering)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class FinancialInvestmentScamDetector(BaseDetector):
    """Detects financial/investment scams: investment_context signal,
    guaranteed/unrealistic-return patterns ('double your money', '100% guaranteed',
    'risk-free'), payment pressure, WhatsApp/Telegram-group funnel cues.

    Stage implementation: Stage 5.
    """

    detector_id = "d07_financial_investment"
    name = "Financial / Investment Scams"
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
        """Run financial/investment scam detection (stub)."""
        return self._not_implemented(artifact)
