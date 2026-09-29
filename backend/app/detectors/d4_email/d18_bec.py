"""Detector 18 — Business Email Compromise / BEC (Domain 4: Email & Comms Security)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import (
    Artifact,
    ArtifactType,
    DetectionResult,
    Evidence,
    EvidenceSeverity,
    Verdict,
)

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class BECDetector(BaseDetector):
    """Detects Business Email Compromise: header spoofing + financial urgency."""

    detector_id = "d18_bec"
    name = "Business Email Compromise (BEC)"
    domain = "Email & Communication Security"
    domain_id = "d4"
    accepted_artifact_types = [ArtifactType.EMAIL]
    required_engines = ["email", "nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        email_sig = await ctx.get_email_signals()
        nlp = await ctx.get_nlp_signals()

        score = 0.0
        evidence: list[Evidence] = []

        # Header authentication failures
        if email_sig.from_reply_to_mismatch:
            score += 0.25
            evidence.append(Evidence(source_engine="email", severity=EvidenceSeverity.HIGH,
                description="From/Reply-To domain mismatch — classic BEC indicator",
                rule_id="email_reply_to_mismatch"))

        if email_sig.display_name_spoofing:
            score += 0.25
            evidence.append(Evidence(source_engine="email", severity=EvidenceSeverity.CRITICAL,
                description="Display name spoofs a known brand/executive",
                rule_id="email_display_name_spoof"))

        if email_sig.spf_pass is False:
            score += 0.15
            evidence.append(Evidence(source_engine="email", severity=EvidenceSeverity.HIGH,
                description="SPF check failed — email sender not authorised",
                rule_id="email_spf_fail"))

        if email_sig.dkim_pass is False:
            score += 0.10
            evidence.append(Evidence(source_engine="email", severity=EvidenceSeverity.MEDIUM,
                description="DKIM signature failed", rule_id="email_dkim_fail"))

        # NLP signals — BEC often requests wire transfers urgently
        if nlp.financial_intent >= 0.25:
            score += nlp.financial_intent * 0.15
            evidence.append(Evidence(source_engine="nlp", severity=EvidenceSeverity.HIGH,
                description=f"Financial transaction language detected (score={nlp.financial_intent:.2f})",
                rule_id="nlp_financial_intent"))

        if nlp.urgency >= 0.30:
            score += nlp.urgency * 0.10

        score = round(min(1.0, score), 4)
        verdict = (Verdict.MALICIOUS if score >= 0.70
                   else Verdict.LIKELY_MALICIOUS if score >= 0.45
                   else Verdict.SUSPICIOUS if score >= 0.20
                   else Verdict.SAFE)

        return self._result(artifact, score, verdict, evidence,
                            signals=["email.from_reply_to_mismatch", "email.display_name_spoofing",
                                     "email.spf_pass", "nlp.financial_intent"])
