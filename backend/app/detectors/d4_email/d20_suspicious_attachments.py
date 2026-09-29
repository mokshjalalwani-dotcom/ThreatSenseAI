"""Detector 20 — Suspicious Attachments (Domain 4: Email & Communication Security)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class SuspiciousAttachmentsDetector(BaseDetector):
    """Static-only attachment analysis: SHA-256 + threat-intel hash lookup,
    magic-byte vs extension vs declared-MIME mismatch, double extensions
    (invoice.pdf.exe), dangerous type list (exe/scr/js/vbs/lnk/iso/hta/jar/
    macro-enabled Office), archive inspection with zip-bomb protection and
    nesting-depth limits, password-protected archive flag, Office macro/OLE
    indicators (oletools/olefile), PDF risk markers (JavaScript, OpenAction,
    embedded files), starter YARA ruleset.

    Stage implementation: Stage 7.
    """

    detector_id = "d20_suspicious_attachments"
    name = "Suspicious Attachments"
    domain = "Email & Communication Security"
    domain_id = "d4"
    accepted_artifact_types = [ArtifactType.EMAIL, ArtifactType.FILE]
    required_engines = ["email", "intel"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run suspicious attachment detection (stub)."""
        return self._not_implemented(artifact)
