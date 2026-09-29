"""Detector 22 — Screenshot Scam Detection (Domain 5: Multimedia & Image-Based)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class ScreenshotScamDetector(BaseDetector):
    """Detects scams in screenshots: OCR via Media Engine → text → NLPEngine
    signals + rule lexicons + URL engine on extracted URLs; handles chat
    screenshots (WhatsApp/Telegram/SMS layouts) and fake payment-success
    screenshots via text cues only. Reports OCR confidence and warns when low.

    Stage implementation: Stage 8.
    """

    detector_id = "d22_screenshot_scam"
    name = "Screenshot Scam Detection"
    domain = "Multimedia & Image-Based"
    domain_id = "d5"
    accepted_artifact_types = [ArtifactType.IMAGE]
    required_engines = ["media", "nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run screenshot scam detection (stub)."""
        return self._not_implemented(artifact)
