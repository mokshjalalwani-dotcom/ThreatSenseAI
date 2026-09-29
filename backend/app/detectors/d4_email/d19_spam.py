"""Detector 19 — Spam (Domain 4: Email & Communication Security)."""

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
class SpamDetector(BaseDetector):
    """Detects unsolicited bulk email: reward language + auth failures + URL density."""

    detector_id = "d19_spam"
    name = "Spam Email"
    domain = "Email & Communication Security"
    domain_id = "d4"
    accepted_artifact_types = [ArtifactType.EMAIL, ArtifactType.SMS]
    required_engines = ["email", "nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        email_sig = await ctx.get_email_signals()
        nlp = await ctx.get_nlp_signals()

        score = 0.0
        evidence: list[Evidence] = []

        # Many URLs + unsubscribe-less body = spam indicator
        url_count = len(email_sig.extracted_urls)
        if url_count >= 5:
            score += min(0.20, url_count * 0.03)
            evidence.append(Evidence(source_engine="email", severity=EvidenceSeverity.MEDIUM,
                description=f"Email contains {url_count} URLs — mass-mail indicator",
                rule_id="email_url_count"))

        if email_sig.spf_pass is False:
            score += 0.15
            evidence.append(Evidence(source_engine="email", severity=EvidenceSeverity.MEDIUM,
                description="SPF failed — bulk sender not authorised", rule_id="email_spf_fail"))

        if nlp.reward_scarcity >= 0.25:
            score += nlp.reward_scarcity * 0.25
            evidence.append(Evidence(source_engine="nlp", severity=EvidenceSeverity.MEDIUM,
                description=f"Promotional/reward language (score={nlp.reward_scarcity:.2f})",
                rule_id="nlp_reward_scarcity"))

        if nlp.scam_intent >= 0.25:
            score += nlp.scam_intent * 0.20
            evidence.append(Evidence(source_engine="nlp", severity=EvidenceSeverity.HIGH,
                description=f"Scam intent detected (score={nlp.scam_intent:.2f})",
                rule_id="nlp_scam_intent"))

        score = round(min(1.0, score), 4)
        verdict = (Verdict.MALICIOUS if score >= 0.70
                   else Verdict.LIKELY_MALICIOUS if score >= 0.45
                   else Verdict.SUSPICIOUS if score >= 0.20
                   else Verdict.SAFE)

        return self._result(artifact, score, verdict, evidence)
