"""
Shared helpers for Domain 1 (Phishing & Social Engineering) detectors.

Keeps each detector file focused on its detection logic rather than
boilerplate result-building and scoring.
"""

from __future__ import annotations

from app.schemas.schemas import (
    Evidence,
    EvidenceSeverity,
    NLPSignals,
    Verdict,
)


def score_from_signals(
    signal_weights: dict[str, tuple[float, float]],
) -> float:
    """Compute a weighted sum score from {name: (value, weight)} dict.

    Args:
        signal_weights: Mapping of signal name to (score_0_1, weight) tuples.

    Returns:
        Weighted sum capped at 1.0.
    """
    total = sum(v * w for v, w in signal_weights.values())
    return round(min(1.0, total), 4)


def nlp_verdict(score: float) -> Verdict:
    """Convert a [0,1] score to a Verdict."""
    if score >= 0.75:
        return Verdict.MALICIOUS
    if score >= 0.50:
        return Verdict.LIKELY_MALICIOUS
    if score >= 0.30:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


def build_evidence(
    nlp: NLPSignals,
    source: str,
    signal_weights: dict[str, tuple[float, float]],
    threshold: float = 0.20,
) -> list[Evidence]:
    """Build Evidence list from NLPSignals for signals that exceed threshold.

    Args:
        nlp:            The NLPSignals object.
        source:         Engine source name (e.g. "nlp").
        signal_weights: {signal_name: (value, weight)} from score_from_signals.
        threshold:      Minimum signal value to include in evidence.

    Returns:
        List of Evidence items, sorted by severity.
    """
    severity_map: dict[str, EvidenceSeverity] = {
        "phishing_intent":          EvidenceSeverity.CRITICAL,
        "scam_intent":              EvidenceSeverity.CRITICAL,
        "credential_request":       EvidenceSeverity.HIGH,
        "remote_access_request":    EvidenceSeverity.HIGH,
        "payment_request":          EvidenceSeverity.HIGH,
        "urgency":                  EvidenceSeverity.MEDIUM,
        "fear":                     EvidenceSeverity.MEDIUM,
        "manipulation":             EvidenceSeverity.MEDIUM,
        "authority":                EvidenceSeverity.MEDIUM,
        "financial_intent":         EvidenceSeverity.MEDIUM,
        "reward_scarcity":          EvidenceSeverity.LOW,
        "investment_context":       EvidenceSeverity.LOW,
        "recruitment_context":      EvidenceSeverity.LOW,
        "tech_support_context":     EvidenceSeverity.LOW,
        "government_service_claim": EvidenceSeverity.MEDIUM,
    }

    descriptions: dict[str, str] = {
        "phishing_intent":          "Phishing intent detected in message text",
        "scam_intent":              "Scam/fraud intent detected in message text",
        "credential_request":       "Message requests credentials, OTP, or personal information",
        "remote_access_request":    "Message requests installation of remote access software",
        "payment_request":          "Message requests an urgent payment",
        "urgency":                  "Message creates artificial urgency",
        "fear":                     "Message uses fear or threat language",
        "manipulation":             "Message uses psychological manipulation tactics",
        "authority":                "Message claims authority (government/bank/official)",
        "financial_intent":         "Financial transaction or payment language detected",
        "reward_scarcity":          "Message claims prize, reward, or limited offer",
        "investment_context":       "Investment opportunity language detected",
        "recruitment_context":      "Suspicious job/recruitment language detected",
        "tech_support_context":     "Tech-support scam language detected",
        "government_service_claim": "Message claims to be from a government agency",
    }

    evidence: list[Evidence] = []
    for sig_name, (value, _weight) in signal_weights.items():
        if value < threshold:
            continue
        sev = severity_map.get(sig_name, EvidenceSeverity.INFO)
        desc = descriptions.get(sig_name, f"Signal '{sig_name}' triggered")

        # Find a matching evidence span from NLP
        matched = None
        for span in nlp.evidence_spans:
            if sig_name in span.signal:
                matched = span.matched_text
                break

        evidence.append(Evidence(
            source_engine=source,
            severity=sev,
            description=f"{desc} (score={value:.2f})",
            matched_text=matched,
            rule_id=f"nlp_{sig_name}",
            metadata={"signal": sig_name, "score": value},
        ))

    return evidence
