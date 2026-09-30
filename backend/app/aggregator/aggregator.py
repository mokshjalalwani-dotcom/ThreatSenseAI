"""
Risk Aggregator — Stage 10: full weighted noisy-OR combination.

Scoring algorithm:
  1. Per-domain score = noisy-OR of all detector scores in that domain.
       noisy_or([s1, s2, ...]) = 1 - product(1-si)
  2. Domain weights loaded from AGGREGATOR_WEIGHTS config (or defaults below).
  3. Overall risk_score = weighted average of domain scores (0-100 scale).
  4. Hard-override rules:
       - Intel hit  → floor score at 0.80 (MALICIOUS)
       - CRITICAL evidence from any detector → floor at 0.70
  5. Top evidence: union of all evidence, sorted by severity, deduplicated.
  6. Primary threat type: domain with highest score.
  7. Recommended actions: rule-based from top signals.
  8. Confidence: average confidence of ran detectors, penalised for errors.
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
    Evidence,
    EvidenceSeverity,
    RiskReport,
    Verdict,
)

logger = logging.getLogger(__name__)

# Domain display names
_DOMAIN_NAMES = {
    "d1": "Phishing & Social Engineering",
    "d2": "URL & Domain Security",
    "d3": "Web & Credential Security",
    "d4": "Email & Communication Security",
    "d5": "Multimedia & Image-Based",
}

# Domain weights for final score combination
_DOMAIN_WEIGHTS: dict[str, float] = {
    "d1": 0.30,   # Phishing / SE (high impact, broad coverage)
    "d2": 0.30,   # URL signals (very reliable)
    "d3": 0.20,   # Web / credential
    "d4": 0.15,   # Email
    "d5": 0.05,   # Media (supplementary)
}

# Severity ordering for sorting
_SEV_ORDER = {
    EvidenceSeverity.CRITICAL: 5,
    EvidenceSeverity.HIGH:     4,
    EvidenceSeverity.MEDIUM:   3,
    EvidenceSeverity.LOW:      2,
    EvidenceSeverity.INFO:     1,
}

_RECOMMENDED_ACTIONS: dict[str, list[str]] = {
    "phishing": [
        "Do NOT enter any credentials or personal information",
        "Do not click any links in this message",
        "Report to your IT/security team immediately",
        "Delete this message without responding",
    ],
    "malware": [
        "Do NOT open or download any attachments",
        "Run a full antivirus scan on your device",
        "Report this to your security team",
    ],
    "scam": [
        "Do NOT send any money or gift cards",
        "Verify via official channels before acting",
        "Report to local cybercrime authority (www.cybercrime.gov.in)",
    ],
    "url": [
        "Do NOT visit the linked URL",
        "If already visited, clear browser cache and run a security scan",
    ],
    "safe": [
        "No immediate action required",
        "Stay vigilant and verify sender identity for important requests",
    ],
}


def _noisy_or(scores: list[float]) -> float:
    """Noisy-OR combination: 1 - product(1 - si). Returns value in [0, 1]."""
    if not scores:
        return 0.0
    product = 1.0
    for s in scores:
        product *= (1.0 - max(0.0, min(1.0, s)))
    return 1.0 - product


def _verdict_from_score(score_0_100: float) -> Verdict:
    if score_0_100 >= 75:
        return Verdict.MALICIOUS
    if score_0_100 >= 50:
        return Verdict.LIKELY_MALICIOUS
    if score_0_100 >= 25:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


def _primary_threat_type(domain_scores: dict[str, float], results: list[DetectionResult]) -> str | None:
    """Determine the primary threat category from top-scoring domain + evidence."""
    if not domain_scores:
        return None
    top_domain = max(domain_scores, key=lambda d: domain_scores[d])
    if domain_scores[top_domain] < 0.20:
        return None

    domain_threats = {
        "d1": "Phishing/Social Engineering",
        "d2": "Malicious URL",
        "d3": "Credential Harvesting / Malicious Webpage",
        "d4": "Email Fraud (BEC/Spam)",
        "d5": "Image-Based Threat (QR/Screenshot Scam)",
    }
    return domain_threats.get(top_domain)


def _get_actions(primary_threat: str | None, verdict: Verdict) -> list[str]:
    if verdict == Verdict.SAFE:
        return _RECOMMENDED_ACTIONS["safe"]
    if not primary_threat:
        return _RECOMMENDED_ACTIONS["safe"]
    pt = primary_threat.lower()
    if "phishing" in pt or "social" in pt or "bec" in pt:
        return _RECOMMENDED_ACTIONS["phishing"]
    if "url" in pt:
        return _RECOMMENDED_ACTIONS["url"]
    if "credential" in pt or "auth" in pt:
        return _RECOMMENDED_ACTIONS["phishing"]
    if "email" in pt:
        return _RECOMMENDED_ACTIONS["scam"]
    if "scam" in pt or "fraud" in pt:
        return _RECOMMENDED_ACTIONS["scam"]
    return _RECOMMENDED_ACTIONS["phishing"]


class RiskAggregator:
    """Full weighted noisy-OR risk aggregator."""

    async def aggregate(
        self,
        artifact: Artifact,
        results: list[DetectionResult],
        engine_signals: EngineSignals | None = None,
        nlp_backend_used: str | None = None,
        errors: list[str] | None = None,
        skipped: list[str] | None = None,
    ) -> RiskReport:
        """Compute the final RiskReport from all DetectionResults."""
        errors = errors or []
        skipped = skipped or []

        # ── 1. Group by domain ────────────────────────────────────────────────
        by_domain: dict[str, list[DetectionResult]] = defaultdict(list)
        for r in results:
            by_domain[r.domain_id].append(r)

        # ── 2. Per-domain noisy-OR scores ─────────────────────────────────────
        domain_scores: dict[str, float] = {}
        per_domain_breakdowns: list[DomainBreakdown] = []

        for did, drs in sorted(by_domain.items()):
            ran = [d for d in drs if d.ran and d.verdict not in (Verdict.NOT_IMPLEMENTED, Verdict.ERROR)]
            scores = [d.score for d in ran]
            domain_score = _noisy_or(scores)
            domain_scores[did] = domain_score

            per_domain_breakdowns.append(DomainBreakdown(
                domain_id=did,
                domain_name=_DOMAIN_NAMES.get(did, did),
                score=round(domain_score, 4),
                detector_count=len(drs),
                detectors_ran=len(ran),
                detectors=drs,
            ))

        # ── 3. Weighted overall score ──────────────────────────────────────────
        weighted_sum = 0.0
        weight_total = 0.0
        for did, ds in domain_scores.items():
            w = _DOMAIN_WEIGHTS.get(did, 0.10)
            weighted_sum += ds * w
            weight_total += w

        raw_score = weighted_sum / weight_total if weight_total > 0 else 0.0

        # Hard boost: if any single domain scores very high it must at least
        # become SUSPICIOUS regardless of other domain weights.
        max_domain_score = max(domain_scores.values(), default=0.0)
        if max_domain_score >= 0.80:
            raw_score = max(raw_score, 0.50)   # floor at LIKELY_MALICIOUS
        elif max_domain_score >= 0.60:
            raw_score = max(raw_score, 0.25)   # floor at SUSPICIOUS

        # ── 4. Hard override: intel hit ────────────────────────────────────────
        intel_hit = (engine_signals and engine_signals.intel
                     and bool(engine_signals.intel.hits))
        if intel_hit:
            raw_score = max(raw_score, 0.80)
            logger.info("Intel hit — score floored at 0.80")

        # Hard override: any CRITICAL evidence
        all_evidence: list[Evidence] = []
        for r in results:
            all_evidence.extend(r.evidence)

        has_critical = any(e.severity == EvidenceSeverity.CRITICAL for e in all_evidence)
        if has_critical:
            raw_score = max(raw_score, 0.70)

        risk_score_100 = round(raw_score * 100, 2)
        verdict = _verdict_from_score(risk_score_100)

        # ── 5. Top evidence (deduplicated, severity-sorted) ───────────────────
        seen_descs: set[str] = set()
        unique_evidence: list[Evidence] = []
        for ev in sorted(all_evidence, key=lambda e: _SEV_ORDER.get(e.severity, 0), reverse=True):
            key = ev.description[:60]
            if key not in seen_descs:
                seen_descs.add(key)
                unique_evidence.append(ev)
        top_evidence = unique_evidence[:10]

        # ── 6. Secondary tags ─────────────────────────────────────────────────
        secondary_tags: list[str] = []
        for did, ds in domain_scores.items():
            if ds >= 0.20 and did in _DOMAIN_NAMES:
                secondary_tags.append(_DOMAIN_NAMES[did].split(" ")[0])

        # ── 7. Confidence ─────────────────────────────────────────────────────
        ran_results = [r for r in results if r.ran]
        confidence = (
            round(sum(r.confidence for r in ran_results) / len(ran_results), 3)
            if ran_results else 0.0
        )
        # Penalise for errors
        if errors:
            confidence = max(0.0, confidence - 0.05 * len(errors))

        # ── 8. Primary threat + recommended actions ───────────────────────────
        primary_threat = _primary_threat_type(domain_scores, results)
        actions = _get_actions(primary_threat, verdict)

        return RiskReport(
            artifact_id=artifact.id,
            artifact_type=artifact.type,
            risk_score=risk_score_100,
            verdict=verdict,
            primary_threat_type=primary_threat,
            secondary_tags=secondary_tags,
            per_domain_scores=per_domain_breakdowns,
            confidence=confidence,
            top_evidence=top_evidence,
            recommended_actions=actions,
            engine_signals=engine_signals,
            nlp_backend_used=nlp_backend_used,
            skipped_components=skipped,
            errors=errors,
            completed_at=datetime.utcnow(),
        )
