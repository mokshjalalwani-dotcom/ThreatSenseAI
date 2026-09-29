"""Detector 21 — QR Phishing / Quishing (Domain 5: Multimedia & Image-Based)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class QRPhishingDetector(BaseDetector):
    """Detects QR phishing (Quishing): decodes QR payload via Media Engine;
    if URL, runs the full URL pipeline (Domain 2 detectors + redirects);
    classifies other payload types (upi://pay with unexpected payee, tel:
    premium, sms: prefilled, WiFi, vCard); shows decoded payload defanged;
    never auto-opens anything.

    Stage implementation: Stage 8.
    """

    detector_id = "d21_qr_phishing"
    name = "QR Phishing (Quishing)"
    domain = "Multimedia & Image-Based"
    domain_id = "d5"
    accepted_artifact_types = [ArtifactType.QR, ArtifactType.IMAGE]
    required_engines = ["media", "url", "intel"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run QR phishing detection (stub)."""
        return self._not_implemented(artifact)
