"""Detector 15 — Credential Harvesting (Domain 3: Web & Credential Security)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class CredentialHarvestingDetector(BaseDetector):
    """Detects credential-harvesting forms and messages: password/OTP/card/CVV/PIN
    fields, MFA/recovery-code requests (account-takeover indicators), forms posting
    to a different domain or over HTTP, NLP credential_request signal. Works on
    webpages and pure message text (email/SMS).

    Stage implementation: Stage 6.
    """

    detector_id = "d15_credential_harvesting"
    name = "Credential Harvesting"
    domain = "Web & Credential Security"
    domain_id = "d3"
    accepted_artifact_types = [
        ArtifactType.WEBPAGE,
        ArtifactType.EMAIL,
        ArtifactType.SMS,
    ]
    required_engines = ["web", "nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run credential harvesting detection (stub)."""
        return self._not_implemented(artifact)
