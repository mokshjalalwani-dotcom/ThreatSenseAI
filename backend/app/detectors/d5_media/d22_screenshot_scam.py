"""Detector 22 — Screenshot Scam / Image-Based Threat (Domain 5)."""

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
class ScreenshotScamDetector(BaseDetector):
    """Detects image-based scams: OCR text → NLP pipeline → threat scoring."""

    detector_id = "d22_screenshot_scam"
    name = "Screenshot / Image-Based Scam"
    domain = "Multimedia & Image-Based Threats"
    domain_id = "d5"
    accepted_artifact_types = [ArtifactType.IMAGE]
    required_engines = ["media", "nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        # Extract text via OCR
        ocr_text = await ctx.get_media_ocr_text()

        if not ocr_text.strip():
            return self._result(artifact, 0.0, Verdict.SAFE,
                                [Evidence(source_engine="media", severity=EvidenceSeverity.INFO,
                                    description="No text found in image via OCR",
                                    rule_id="media_ocr_empty")],
                                signals=["media.ocr"])

        evidence: list[Evidence] = []
        evidence.append(Evidence(source_engine="media", severity=EvidenceSeverity.INFO,
            description=f"OCR extracted {len(ocr_text)} characters from image",
            matched_text=ocr_text[:120], rule_id="media_ocr_text"))

        # Analyse extracted text with NLP engine
        if ctx._nlp_engine:
            nlp = await ctx._nlp_engine.analyze(ocr_text)
        else:
            from app.engines.nlp.backends.rules import RulesBackend
            nlp = await RulesBackend().analyze(ocr_text)

        score = 0.0
        if nlp.phishing_intent >= 0.25:
            score += nlp.phishing_intent * 0.35
            evidence.append(Evidence(source_engine="nlp", severity=EvidenceSeverity.HIGH,
                description=f"Phishing intent in OCR text ({nlp.phishing_intent:.2f})",
                rule_id="nlp_phishing_intent"))

        if nlp.scam_intent >= 0.25:
            score += nlp.scam_intent * 0.25
            evidence.append(Evidence(source_engine="nlp", severity=EvidenceSeverity.HIGH,
                description=f"Scam intent in OCR text ({nlp.scam_intent:.2f})",
                rule_id="nlp_scam_intent"))

        if nlp.credential_request >= 0.25:
            score += nlp.credential_request * 0.20
            evidence.append(Evidence(source_engine="nlp", severity=EvidenceSeverity.HIGH,
                description=f"Credential request in OCR text ({nlp.credential_request:.2f})",
                rule_id="nlp_credential_request"))

        if nlp.urgency >= 0.25:
            score += nlp.urgency * 0.10

        if nlp.reward_scarcity >= 0.25:
            score += nlp.reward_scarcity * 0.10

        score = round(min(1.0, score), 4)
        verdict = (Verdict.MALICIOUS if score >= 0.70
                   else Verdict.LIKELY_MALICIOUS if score >= 0.45
                   else Verdict.SUSPICIOUS if score >= 0.20
                   else Verdict.SAFE)

        return self._result(artifact, score, verdict, evidence, signals=["media.ocr", "nlp.phishing_intent"])
