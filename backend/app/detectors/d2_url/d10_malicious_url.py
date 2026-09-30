"""Detector 10 — Malicious URL (Domain 2: URL & Domain Security)."""

from __future__ import annotations

import time
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

# Score → verdict thresholds
_T_SUSPICIOUS = 0.35
_T_LIKELY = 0.55
_T_MALICIOUS = 0.75


@register_detector
class MaliciousURLDetector(BaseDetector):
    """Classifies URLs as malicious using XGBoost (or rule-based fallback) on
    URL structural features.  Returns SHAP top-5 feature explanations.

    Inputs: url/email/sms/webpage artifacts (runs on primary URL + sub-artifacts).
    """

    detector_id = "d10_malicious_url"
    name = "Malicious URL"
    domain = "URL & Domain Security"
    domain_id = "d2"
    accepted_artifact_types = [
        ArtifactType.URL,
        ArtifactType.EMAIL,
        ArtifactType.SMS,
        ArtifactType.WEBPAGE,
    ]
    required_engines = ["url", "intel"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run malicious URL detection."""
        t0 = time.perf_counter()

        # Get the URL to analyse
        url = _get_url(artifact)
        if not url:
            return self._error(artifact, "No URL found in artifact")

        try:
            signals = await ctx.get_url_signals(url)
        except Exception as exc:
            return self._error(artifact, str(exc))

        risk = signals.risk_score or 0.0
        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Build evidence
        evidence: list[Evidence] = []

        # SHAP / feature importance evidence
        for feat in (signals.shap_top_features or [])[:5]:
            name = feat.get("name", "")
            val = feat.get("value", 0)
            imp = feat.get("importance", 0)
            if abs(imp) < 0.01:
                continue
            direction = "increases" if imp > 0 else "decreases"
            evidence.append(Evidence(
                source_engine="url",
                severity=_severity(abs(imp)),
                description=(
                    f"Feature '{name}'={val:.3g} {direction} malicious probability "
                    f"by {abs(imp):.3f}"
                ),
                rule_id=f"shap_{name}",
                metadata={"feature": name, "value": val, "shap": imp},
            ))

        # Suspicious token evidence
        if signals.suspicious_tokens:
            evidence.append(Evidence(
                source_engine="url",
                severity=EvidenceSeverity.MEDIUM,
                description=(
                    f"URL contains {len(signals.suspicious_tokens)} suspicious token(s): "
                    + ", ".join(f"'{t}'" for t in signals.suspicious_tokens[:5])
                ),
                rule_id="suspicious_tokens",
            ))

        # IP host
        if signals.is_ip_host:
            evidence.append(Evidence(
                source_engine="url",
                severity=EvidenceSeverity.HIGH,
                description="Host is an IP address — legitimate services use domain names",
                rule_id="ip_host",
            ))

        # Punycode
        if signals.has_punycode:
            evidence.append(Evidence(
                source_engine="url",
                severity=EvidenceSeverity.HIGH,
                description="URL contains Punycode (xn--) — potential IDN homograph attack",
                rule_id="punycode",
            ))

        verdict = _score_to_verdict(risk)
        confidence = min(0.85, max(0.4, risk * 1.1)) if risk > 0.2 else 0.5

        return DetectionResult(
            detector_id=self.detector_id,
            name=self.name,
            domain=self.domain,
            domain_id=self.domain_id,
            score=round(risk, 4),
            verdict=verdict,
            confidence=round(confidence, 3),
            evidence=evidence,
            signals_used=["url.risk_score", "url.shap_top_features", "url.suspicious_tokens"],
            metadata={"elapsed_ms": round(elapsed_ms, 2)},
        )

    def _error(self, artifact: Artifact, msg: str) -> DetectionResult:
        return DetectionResult(
            detector_id=self.detector_id,
            name=self.name,
            domain=self.domain,
            domain_id=self.domain_id,
            score=0.0,
            verdict=Verdict.ERROR,
            confidence=0.0,
            evidence=[],
            error=msg,
        )


def _get_url(artifact: Artifact) -> str:
    """Return the best URL to analyse from this artifact.

    Rules:
    - URL artifact  → use normalized_url or raw_content (it IS a URL).
    - EMAIL/SMS     → use first extracted_url from body; skip if none.
    - WEBPAGE       → use normalized_url (the source URL) only; skip file uploads.
    - Anything else → skip.
    """
    if artifact.type == ArtifactType.URL:
        return (artifact.normalized_url or artifact.raw_content or "").strip()

    if artifact.type in (ArtifactType.EMAIL, ArtifactType.SMS):
        urls = artifact.extracted_urls or []
        return urls[0].strip() if urls else ""

    if artifact.type == ArtifactType.WEBPAGE:
        # normalized_url is only set when a URL string was submitted;
        # file-uploaded HTML pages have no source URL to score.
        return (artifact.normalized_url or "").strip()

    return ""


def _score_to_verdict(score: float) -> Verdict:
    if score >= _T_MALICIOUS:
        return Verdict.MALICIOUS
    if score >= _T_LIKELY:
        return Verdict.LIKELY_MALICIOUS
    if score >= _T_SUSPICIOUS:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


def _severity(importance: float) -> EvidenceSeverity:
    if importance >= 0.2:
        return EvidenceSeverity.HIGH
    if importance >= 0.1:
        return EvidenceSeverity.MEDIUM
    return EvidenceSeverity.LOW
