"""Detector 11 — Brand/Domain Impersonation (Domain 2: URL & Domain Security)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.engines.url.brands import BrandHit, check_brand_impersonation
from app.engines.url.features import extract_features
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

# Per-match-type severity weights (0-1 contribution to score)
_TYPE_WEIGHTS: dict[str, float] = {
    "exact_domain": 0.0,    # Not a hit
    "subdomain": 0.80,
    "path": 0.60,
    "fuzzy": 0.70,
    "alias": 0.85,
    "skeleton": 0.95,       # IDN homograph — near certain
}


@register_detector
class BrandImpersonationDetector(BaseDetector):
    """Detects brand impersonation via:
    - Brand name in subdomain (paypal.evil.com)
    - Brand name in path (evil.com/paypal/login)
    - Fuzzy domain similarity (paypa1-secure.com)
    - Known typosquat aliases (paytms.com)
    - Edit-distance typosquatting (≤2 edits from brand name)

    Works on URL, Email, SMS, and Webpage artifacts.
    """

    detector_id = "d11_brand_impersonation"
    name = "Brand/Domain Impersonation"
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
        url = _resolve_url(artifact)
        if not url:
            return self._no_hit(artifact)

        try:
            feats = extract_features(url)
        except Exception as exc:
            return self._error(artifact, str(exc))

        hits = check_brand_impersonation(
            registered_domain=feats.registered_domain,
            subdomain=feats.subdomain,
            path=feats.path,
            url=url,
            domain=feats.domain,
        )

        if not hits:
            return self._no_hit(artifact)

        # Score = max weighted hit similarity
        top_hit: BrandHit = hits[0]
        base_weight = _TYPE_WEIGHTS.get(top_hit.match_type, 0.5)
        score = round(min(1.0, top_hit.similarity * base_weight), 4)

        evidence: list[Evidence] = []
        for hit in hits[:5]:
            sev = EvidenceSeverity.CRITICAL if hit.similarity >= 0.9 else EvidenceSeverity.HIGH
            evidence.append(Evidence(
                source_engine="url",
                severity=sev,
                description=hit.evidence_text,
                matched_text=hit.matched_term,
                rule_id=f"brand_{hit.match_type}_{hit.brand_key}",
                metadata={
                    "brand": hit.brand_key,
                    "display_name": hit.display_name,
                    "match_type": hit.match_type,
                    "similarity": hit.similarity,
                    "edit_distance": hit.edit_distance,
                },
            ))

        verdict = Verdict.MALICIOUS if score >= 0.7 else (
            Verdict.LIKELY_MALICIOUS if score >= 0.5 else Verdict.SUSPICIOUS
        )

        return DetectionResult(
            detector_id=self.detector_id,
            name=self.name,
            domain=self.domain,
            domain_id=self.domain_id,
            score=score,
            verdict=verdict,
            confidence=round(min(0.95, score + 0.1), 3),
            evidence=evidence,
            signals_used=["url.registered_domain", "url.subdomain", "url.path"],
        )

    def _no_hit(self, artifact: Artifact) -> DetectionResult:
        return DetectionResult(
            detector_id=self.detector_id,
            name=self.name,
            domain=self.domain,
            domain_id=self.domain_id,
            score=0.0,
            verdict=Verdict.SAFE,
            confidence=0.7,
            evidence=[],
            signals_used=["url.registered_domain", "url.subdomain"],
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


def _resolve_url(artifact: Artifact) -> str:
    """Return a real URL from the artifact — never raw HTML or plain SMS body."""
    if artifact.type == ArtifactType.URL:
        return (artifact.normalized_url or artifact.raw_content or "").strip()
    if artifact.type in (ArtifactType.EMAIL, ArtifactType.SMS):
        urls = artifact.extracted_urls or []
        return urls[0].strip() if urls else ""
    if artifact.type == ArtifactType.WEBPAGE:
        return (artifact.normalized_url or "").strip()
    return ""

