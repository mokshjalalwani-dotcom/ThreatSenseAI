"""
BaseDetector — abstract base class for all 22 detectors.

Contract
--------
Every concrete detector MUST:
  1. Be decorated with ``@register_detector`` to self-register.
  2. Define class-level attributes: detector_id, name, domain, domain_id,
     accepted_artifact_types, required_engines.
  3. Implement ``detect(artifact, ctx) -> DetectionResult``.
  4. NEVER raise exceptions into the aggregator; all errors go into
     DetectionResult.error and verdict=ERROR.
  5. NEVER embed its own model or duplicate feature extraction — call engines
     via ctx instead.

Helper
------
``_not_implemented()`` is provided so that Stage-1 stubs can return a valid
DetectionResult in one line.  Remove the call once the detector is built.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

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


class BaseDetector(ABC):
    """Abstract base for every detector in the registry.

    Class attributes (override in every subclass)
    ----------------------------------------------
    detector_id             : str   — globally unique snake_case id, e.g. "d01_email_phishing"
    name                    : str   — human-readable name shown in the UI
    domain                  : str   — human-readable domain name
    domain_id               : str   — one of d1 … d5
    accepted_artifact_types : list  — ArtifactType values this detector handles
    required_engines        : list  — engine names this detector will call via ctx
    version                 : str   — semver; bump when the detector logic changes
    """

    detector_id: str = ""
    name: str = ""
    domain: str = ""
    domain_id: str = ""
    accepted_artifact_types: list[ArtifactType] = []
    required_engines: list[str] = []
    version: str = "0.1.0"

    @abstractmethod
    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        """Run this detector against *artifact* using shared engine signals from *ctx*.

        Args:
            artifact: The artifact to analyse.
            ctx:      Shared AnalysisContext — call ctx.get_nlp_signals() etc.

        Returns:
            A DetectionResult.  MUST NOT raise.
        """

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _not_implemented(self, artifact: Artifact) -> DetectionResult:
        """Return a placeholder NOT_IMPLEMENTED result (used by Stage-1 stubs)."""
        return DetectionResult(
            detector_id=self.detector_id,
            name=self.name,
            domain=self.domain,
            domain_id=self.domain_id,
            score=0.0,
            verdict=Verdict.NOT_IMPLEMENTED,
            confidence=0.0,
            evidence=[
                Evidence(
                    source_engine="registry",
                    severity=EvidenceSeverity.INFO,
                    description=(
                        f"Detector '{self.name}' is a registered stub. "
                        "Full implementation will be added in a future stage."
                    ),
                )
            ],
            signals_used=self.required_engines,
            error=f"Detector '{self.name}' not yet implemented.",
            ran=False,
        )

    def _skipped(self, artifact: Artifact) -> DetectionResult:
        """Return a SKIPPED result when the artifact type is not handled."""
        return DetectionResult(
            detector_id=self.detector_id,
            name=self.name,
            domain=self.domain,
            domain_id=self.domain_id,
            score=0.0,
            verdict=Verdict.UNKNOWN,
            confidence=0.0,
            evidence=[],
            signals_used=[],
            error=None,
            ran=False,
        )

    def accepts(self, artifact_type: ArtifactType) -> bool:
        """Return True if this detector handles the given artifact type."""
        return artifact_type in self.accepted_artifact_types

    def _result(
        self,
        artifact: Artifact,
        score: float,
        verdict: Verdict,
        evidence: list[Evidence],
        signals: list[str] | None = None,
    ) -> DetectionResult:
        """Convenience factory for a fully populated DetectionResult."""
        confidence = round(min(0.95, score + 0.08), 3)
        return DetectionResult(
            detector_id=self.detector_id,
            name=self.name,
            domain=self.domain,
            domain_id=self.domain_id,
            score=round(score, 4),
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
            signals_used=signals or self.required_engines,
        )

