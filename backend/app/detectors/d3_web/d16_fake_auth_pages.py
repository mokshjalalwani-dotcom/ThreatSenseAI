"""Detector 16 — Fake Auth Pages (Domain 3: Web & Credential Security)."""

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
class FakeAuthPagesDetector(BaseDetector):
    """Detects fake login/auth pages: brand claim + credential fields + URL mismatch."""

    detector_id = "d16_fake_auth_pages"
    name = "Fake Authentication Page"
    domain = "Web & Credential Security"
    domain_id = "d3"
    accepted_artifact_types = [ArtifactType.WEBPAGE, ArtifactType.URL]
    required_engines = ["web", "url", "nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        web = await ctx.get_web_signals()
        nlp = await ctx.get_nlp_signals()

        score = 0.0
        evidence: list[Evidence] = []

        # Brand claimed in page title/H1 but URL doesn't match brand domain
        if web.claimed_brand:
            score += 0.25
            evidence.append(Evidence(source_engine="web", severity=EvidenceSeverity.HIGH,
                description=f"Page claims to be '{web.claimed_brand}' login page",
                matched_text=web.claimed_brand, rule_id="web_claimed_brand"))

        if web.has_password_field:
            score += 0.25
            evidence.append(Evidence(source_engine="web", severity=EvidenceSeverity.HIGH,
                description="Fake auth page contains password field", rule_id="web_password_field"))

        if web.has_eval_obfuscation:
            score += 0.20
            evidence.append(Evidence(source_engine="web", severity=EvidenceSeverity.HIGH,
                description="Page uses eval()/document.write() JavaScript obfuscation",
                rule_id="web_js_obfuscation"))

        if web.form_posts_to_external_domain:
            score += 0.15
            evidence.append(Evidence(source_engine="web", severity=EvidenceSeverity.HIGH,
                description="Login form submits to external domain", rule_id="web_form_external"))

        if web.external_script_domains:
            score += 0.05
            evidence.append(Evidence(source_engine="web", severity=EvidenceSeverity.LOW,
                description=f"Page loads {len(web.external_script_domains)} external scripts",
                rule_id="web_external_scripts"))

        if nlp.phishing_intent >= 0.30:
            score += nlp.phishing_intent * 0.15

        score = round(min(1.0, score), 4)
        verdict = (Verdict.MALICIOUS if score >= 0.70
                   else Verdict.LIKELY_MALICIOUS if score >= 0.45
                   else Verdict.SUSPICIOUS if score >= 0.20
                   else Verdict.SAFE)

        return self._result(artifact, score, verdict, evidence)
