"""
Explainability module — stub for Stage 10.

Full implementation: assemble human-readable explanations from Evidence objects
(rule hits, NLP signal spans, SHAP top features, intel sources, redirect chain,
decoded obfuscation/IDN forms). Every evidence item gets source_engine, severity,
and plain-language text. Produces a 2-3 sentence summary and detailed breakdown.
"""

from __future__ import annotations

import logging

from app.schemas.schemas import Evidence, RiskReport

logger = logging.getLogger(__name__)


class Explainer:
    """Builds human-readable explanations for a RiskReport.

    Stage 1: stub — returns the report unchanged.
    Stage 10: full explanation assembly with NLP span highlighting, SHAP charts,
              redirect-chain rendering, defanged URLs.
    """

    def explain(self, report: RiskReport) -> RiskReport:
        """Enrich *report* with assembled explanations.

        Args:
            report: A RiskReport produced by the aggregator.

        Returns:
            The same report, potentially with enriched top_evidence and
            recommended_actions (stub: returns unchanged).
        """
        logger.debug("Explainer.explain called (stub)")
        return report

    def summarise(self, evidence: list[Evidence]) -> str:
        """Produce a plain-language 2-3 sentence summary from evidence items.

        Args:
            evidence: A list of Evidence objects from all detectors.

        Returns:
            A human-readable summary string.
        """
        if not evidence:
            return "No evidence was collected — all detectors are stubs in Stage 1."
        return f"{len(evidence)} evidence item(s) collected. Full explanation in Stage 10."
