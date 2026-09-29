"""Detector 06 — Government Impersonation Scams (Domain 1)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.detectors.d1_phishing._nlp_helpers import (
    build_evidence,
    nlp_verdict,
    score_from_signals,
)
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult, Evidence, EvidenceSeverity

if TYPE_CHECKING:
    from app.core.context import AnalysisContext


@register_detector
class GovernmentScamsDetector(BaseDetector):
    """Detects government impersonation scams: RBI/IT/EPFO/UIDAI fraud claims."""

    detector_id = "d06_government_scams"
    name = "Government Impersonation Scam"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [ArtifactType.EMAIL, ArtifactType.SMS, ArtifactType.URL, ArtifactType.WEBPAGE]
    required_engines = ["nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        nlp = await ctx.get_nlp_signals()
        sw = {
            "government_service_claim": (nlp.government_service_claim, 0.40),
            "authority":                (nlp.authority,                0.20),
            "fear":                     (nlp.fear,                     0.15),
            "payment_request":          (nlp.payment_request,          0.15),
            "urgency":                  (nlp.urgency,                  0.10),
        }
        score = score_from_signals(sw)
        evidence = build_evidence(nlp, "nlp", sw)

        if nlp.claimed_org and nlp.government_service_claim >= 0.25:
            evidence.append(Evidence(
                source_engine="nlp",
                severity=EvidenceSeverity.HIGH,
                description=f"Message claims to be from '{nlp.claimed_org}'",
                matched_text=nlp.claimed_org,
                rule_id="nlp_claimed_org",
            ))

        return self._result(artifact, score, nlp_verdict(score), evidence)
