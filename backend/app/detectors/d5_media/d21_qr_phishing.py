"""Detector 21 — QR Code Phishing (Domain 5: Multimedia & Image-Based Threats)."""

from __future__ import annotations

import re
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

_SUSPICIOUS_TLD_RE = re.compile(r"\.(xyz|tk|ml|ga|cf|top|gq|pw|cc|click|link)(/|$)", re.I)
_SHORTENER_RE = re.compile(r"(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|rb\.gy|cutt\.ly)", re.I)
_URL_RE = re.compile(r"https?://[^\s]+", re.I)


@register_detector
class QRPhishingDetector(BaseDetector):
    """Detects QR-code phishing (quishing): decodes QR image, analyses embedded URL."""

    detector_id = "d21_qr_phishing"
    name = "QR Code Phishing (Quishing)"
    domain = "Multimedia & Image-Based Threats"
    domain_id = "d5"
    accepted_artifact_types = [ArtifactType.QR, ArtifactType.IMAGE]
    required_engines = ["media", "url"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        payloads = await ctx.get_media_qr_payloads()

        if not payloads:
            return self._result(artifact, 0.0, Verdict.SAFE, [],
                                signals=["media.qr_decode"])

        score = 0.0
        evidence: list[Evidence] = []

        for payload in payloads[:5]:
            # QR containing a URL is a primary quishing indicator
            if _URL_RE.match(payload.strip()):
                score += 0.15
                evidence.append(Evidence(source_engine="media", severity=EvidenceSeverity.MEDIUM,
                    description=f"QR code contains URL: '{payload[:80]}'",
                    matched_text=payload[:80], rule_id="qr_contains_url"))

                if _SUSPICIOUS_TLD_RE.search(payload):
                    score += 0.35
                    evidence.append(Evidence(source_engine="media", severity=EvidenceSeverity.HIGH,
                        description="QR URL uses high-risk TLD", rule_id="qr_suspicious_tld"))

                if _SHORTENER_RE.search(payload):
                    score += 0.25
                    evidence.append(Evidence(source_engine="media", severity=EvidenceSeverity.HIGH,
                        description="QR URL uses URL shortener (destination hidden)",
                        rule_id="qr_shortener"))

                # Also run URL engine signals
                url_sig = await ctx.get_url_signals(payload.strip())
                if url_sig.risk_score and url_sig.risk_score >= 0.5:
                    score += url_sig.risk_score * 0.20
                    evidence.append(Evidence(source_engine="url", severity=EvidenceSeverity.HIGH,
                        description=f"QR URL risk score: {url_sig.risk_score:.2f}",
                        rule_id="url_risk_score"))
            else:
                # Non-URL QR (text, phone, etc.) — low suspicion
                score += 0.05

        score = round(min(1.0, score), 4)
        verdict = (Verdict.MALICIOUS if score >= 0.70
                   else Verdict.LIKELY_MALICIOUS if score >= 0.45
                   else Verdict.SUSPICIOUS if score >= 0.20
                   else Verdict.SAFE)

        return self._result(artifact, score, verdict, evidence, signals=["media.qr_decode", "url.risk_score"])
