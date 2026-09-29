"""Detector 16 — Fake Authentication Pages (Domain 3: Web & Credential Security)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class FakeAuthPagesDetector(BaseDetector):
    """Detects fake login/authentication pages: login-field presence, claimed brand
    (page title, text, logo alt, brand keywords) vs actual domain mismatch against
    the brand list, form destination mismatch (form action ≠ page domain).

    Stage implementation: Stage 6.
    """

    detector_id = "d16_fake_auth_pages"
    name = "Fake Authentication Pages"
    domain = "Web & Credential Security"
    domain_id = "d3"
    accepted_artifact_types = [ArtifactType.WEBPAGE, ArtifactType.URL]
    required_engines = ["web", "url"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run fake authentication page detection (stub)."""
        return self._not_implemented(artifact)
