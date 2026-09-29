"""Detector 19 — Spam (Domain 4: Email & Communication Security)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class SpamDetector(BaseDetector):
    """Detects spam using text features + structural features (excess links,
    image-only, HTML-to-text ratio, unsubscribe presence) + NLP, plus a
    lightweight classical classifier (logistic regression / LightGBM on
    TF-IDF + structural features) trained on SpamAssassin / Enron-spam /
    SMS Spam Collection. Also uses MinHash/simhash near-duplicate detection.
    Spam is intentionally kept separate from malicious-intent detectors.

    Stage implementation: Stage 7.
    """

    detector_id = "d19_spam"
    name = "Spam"
    domain = "Email & Communication Security"
    domain_id = "d4"
    accepted_artifact_types = [ArtifactType.EMAIL, ArtifactType.SMS]
    required_engines = ["email", "nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run spam detection (stub)."""
        return self._not_implemented(artifact)
