"""Detector 01 — Email Phishing (Domain 1: Phishing & Social Engineering)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.detectors.d1_phishing._nlp_helpers import (
    build_evidence,
    nlp_verdict,
    score_from_signals,
)
from app.schemas.schemas import (
    Artifact,
    ArtifactType,
    DetectionResult,
)

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class EmailPhishingDetector(BaseDetector):
    """Detects phishing emails using NLP signals, sender mismatch, and URL analysis.

    Signals used: urgency, fear, credential_request, phishing_intent,
    from_reply_to_mismatch, display_name_spoofing.
    """

    detector_id = "d01_email_phishing"
    name = "Email Phishing"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [ArtifactType.EMAIL, ArtifactType.URL, ArtifactType.SMS]
    required_engines = ["nlp", "url", "intel"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        nlp = await ctx.get_nlp_signals()
        email = await ctx.get_email_signals()

        # Core phishing signals
        signal_weights = {
            "phishing_intent":    (nlp.phishing_intent,    0.35),
            "credential_request": (nlp.credential_request, 0.25),
            "urgency":            (nlp.urgency,            0.15),
            "fear":               (nlp.fear,               0.10),
            "authority":          (nlp.authority,          0.05),
        }

        # Email-specific header mismatches boost score
        mismatch_boost = 0.0
        if email.from_reply_to_mismatch:
            mismatch_boost += 0.15
        if email.display_name_spoofing:
            mismatch_boost += 0.10
        if email.spf_pass is False:
            mismatch_boost += 0.10

        score = score_from_signals(signal_weights) + mismatch_boost
        score = min(1.0, score)

        evidence = build_evidence(nlp, "nlp", signal_weights)
        if email.from_reply_to_mismatch:
            from app.schemas.schemas import Evidence, EvidenceSeverity
            evidence.append(Evidence(
                source_engine="email",
                severity=EvidenceSeverity.HIGH,
                description="From/Reply-To domain mismatch detected — common phishing tactic",
                rule_id="email_reply_to_mismatch",
            ))

        verdict = nlp_verdict(score)
        return self._result(artifact, score, verdict, evidence,
                            signals=["nlp.phishing_intent", "nlp.credential_request",
                                     "email.from_reply_to_mismatch"])
