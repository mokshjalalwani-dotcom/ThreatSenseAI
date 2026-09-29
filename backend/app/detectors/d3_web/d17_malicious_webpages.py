"""Detector 17 — Malicious Webpages (Domain 3: Web & Credential Security)."""

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
class MaliciousWebpageDetector(BaseDetector):
    """Detects malicious webpages: drive-by, malware distribution, JS obfuscation."""

    detector_id = "d17_malicious_webpages"
    name = "Malicious Webpage"
    domain = "Web & Credential Security"
    domain_id = "d3"
    accepted_artifact_types = [ArtifactType.WEBPAGE, ArtifactType.URL]
    required_engines = ["web", "url", "nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        web = await ctx.get_web_signals()
        url_signals = await ctx.get_url_signals()
        nlp = await ctx.get_nlp_signals()

        score = 0.0
        evidence: list[Evidence] = []

        # JS obfuscation
        if web.has_eval_obfuscation:
            score += 0.35
            evidence.append(Evidence(source_engine="web", severity=EvidenceSeverity.HIGH,
                description="eval()/document.write() obfuscation — drive-by download indicator",
                rule_id="web_js_obfuscation"))

        # Multiple external script domains = supply-chain risk
        n_ext = len(web.external_script_domains)
        if n_ext >= 3:
            score += min(0.20, n_ext * 0.05)
            evidence.append(Evidence(source_engine="web", severity=EvidenceSeverity.MEDIUM,
                description=f"Page loads scripts from {n_ext} external domains",
                rule_id="web_external_scripts"))

        # High link density = low content, possible redirect page
        if web.link_density >= 0.5:
            score += 0.10
            evidence.append(Evidence(source_engine="web", severity=EvidenceSeverity.LOW,
                description=f"Extremely high link density ({web.link_density:.2f})",
                rule_id="web_link_density"))

        # URL-level risk signal
        if url_signals.risk_score and url_signals.risk_score >= 0.5:
            score += url_signals.risk_score * 0.20
            evidence.append(Evidence(source_engine="url", severity=EvidenceSeverity.HIGH,
                description=f"URL risk score: {url_signals.risk_score:.2f}",
                rule_id="url_risk_score"))

        if nlp.scam_intent >= 0.30:
            score += nlp.scam_intent * 0.10

        score = round(min(1.0, score), 4)
        verdict = (Verdict.MALICIOUS if score >= 0.70
                   else Verdict.LIKELY_MALICIOUS if score >= 0.45
                   else Verdict.SUSPICIOUS if score >= 0.20
                   else Verdict.SAFE)

        return self._result(artifact, score, verdict, evidence)
