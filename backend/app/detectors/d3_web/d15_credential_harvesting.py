"""Detector 15 — Credential Harvesting (Domain 3: Web & Credential Security)."""

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
class CredentialHarvestingDetector(BaseDetector):
    """Detects credential-harvesting via DOM signals + NLP credential_request."""

    detector_id = "d15_credential_harvesting"
    name = "Credential Harvesting"
    domain = "Web & Credential Security"
    domain_id = "d3"
    accepted_artifact_types = [ArtifactType.WEBPAGE, ArtifactType.EMAIL, ArtifactType.SMS]
    required_engines = ["web", "nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        web = await ctx.get_web_signals()
        nlp = await ctx.get_nlp_signals()

        score = 0.0
        evidence: list[Evidence] = []

        # DOM signals
        if web.has_password_field:
            score += 0.30
            evidence.append(Evidence(source_engine="web", severity=EvidenceSeverity.HIGH,
                description="Page contains a password input field", rule_id="web_password_field"))
        if web.has_otp_field:
            score += 0.20
            evidence.append(Evidence(source_engine="web", severity=EvidenceSeverity.HIGH,
                description="Page contains an OTP/PIN input field", rule_id="web_otp_field"))
        if web.has_card_field:
            score += 0.25
            evidence.append(Evidence(source_engine="web", severity=EvidenceSeverity.CRITICAL,
                description="Page contains card number/CVV input fields", rule_id="web_card_field"))
        if web.form_posts_to_external_domain:
            score += 0.20
            evidence.append(Evidence(source_engine="web", severity=EvidenceSeverity.HIGH,
                description="Form submits data to external domain", rule_id="web_form_external"))
        if web.form_action_over_http:
            score += 0.10
            evidence.append(Evidence(source_engine="web", severity=EvidenceSeverity.MEDIUM,
                description="Form action uses unencrypted HTTP", rule_id="web_form_http"))

        # NLP signal (for email/SMS artifacts)
        if nlp.credential_request >= 0.30:
            score += nlp.credential_request * 0.25
            evidence.append(Evidence(source_engine="nlp", severity=EvidenceSeverity.HIGH,
                description=f"NLP credential request signal ({nlp.credential_request:.2f})",
                rule_id="nlp_credential_request"))

        score = round(min(1.0, score), 4)
        if score >= 0.70:
            verdict = Verdict.MALICIOUS
        elif score >= 0.45:
            verdict = Verdict.LIKELY_MALICIOUS
        elif score >= 0.20:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.SAFE

        return self._result(artifact, score, verdict, evidence,
                            signals=["web.has_password_field", "web.has_card_field", "nlp.credential_request"])
