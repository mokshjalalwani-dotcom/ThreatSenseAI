"""
Risk Aggregator — stub for Stage 10.

Full implementation: weighted/noisy-OR combination from a versioned YAML
config, hard-override rules (confirmed intel hit sets a score floor),
probability calibration, partial-failure handling, deduplication of
overlapping detections into primary + secondary tags.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime

from app.schemas.schemas import (
    Artifact,
    DetectionResult,
    DomainBreakdown,
    EngineSignals,
    RiskReport,
    Verdict,
)

logger = logging.getLogger(__name__)

# Domain display names (mirrors registry.DOMAIN_NAMES)
_DOMAIN_NAMES = {
    "d1": "Phishing & Social Engineering",
    "d2": "URL & Domain Security",
    "d3": "Web & Credential Security",
    "d4": "Email & Communication Security",
    "d5": "Multimedia & Image-Based",
}


class RiskAggregator:
    """Combines all DetectionResults into a final RiskReport.

    Stage 1: stub — groups results by domain, returns risk_score=0 and
    verdict=UNKNOWN for every artifact (all detectors are stubs themselves).
    Stage 10: full weighted combination, calibration, override rules.
    """

    async def aggregate(
        self,
        artifact: Artifact,
        results: list[DetectionResult],
        engine_signals: EngineSignals | None = None,
        nlp_backend_used: str | None = None,
        errors: list[str] | None = None,
        skipped: list[str] | None = None,
    ) -> RiskReport:
        """Build a RiskReport from detection results.

        Args:
            artifact:          The analysed artifact.
            results:           All DetectionResults (including not-implemented stubs).
            engine_signals:    Snapshot of cached engine signals.
            nlp_backend_used:  Which NLP backend ran.
            errors:            Engine/detector errors to surface.
            skipped:           Components skipped (wrong type, engine unavailable).

        Returns:
            A RiskReport with placeholder scores in Stage 1.
        """
        logger.debug(
            "RiskAggregator.aggregate called (stub) for artifact %s with %d results",
            artifact.id,
            len(results),
        )

        # Group results by domain
        by_domain: dict[str, list[DetectionResult]] = defaultdict(list)
        for r in results:
            by_domain[r.domain_id].append(r)

        per_domain_scores = [
            DomainBreakdown(
                domain_id=did,
                domain_name=_DOMAIN_NAMES.get(did, did),
                score=0.0,
                detector_count=len(drs),
                detectors_ran=sum(1 for d in drs if d.ran),
                detectors=drs,
            )
            for did, drs in sorted(by_domain.items())
        ]

        return RiskReport(
            artifact_id=artifact.id,
            artifact_type=artifact.type,
            risk_score=0.0,
            verdict=Verdict.UNKNOWN,
            primary_threat_type=None,
            secondary_tags=[],
            per_domain_scores=per_domain_scores,
            confidence=0.0,
            top_evidence=[],
            recommended_actions=["Stage 1 stub — full scoring implemented in Stage 10."],
            engine_signals=engine_signals,
            nlp_backend_used=nlp_backend_used,
            skipped_components=skipped or [],
            errors=errors or [],
            completed_at=datetime.utcnow(),
        )
