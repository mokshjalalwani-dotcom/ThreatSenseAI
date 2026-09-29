"""Detector 14 — IDN/Homograph Attack Detection (Domain 2: URL & Domain Security).

Detects Internationalized Domain Name (IDN) attacks:
  - xn-- Punycode labels presence
  - Decoding with idna library and comparing to brand list
  - Mixed-script labels (Latin + Cyrillic, etc.)
  - Unicode confusable skeleton comparison against brand domains
  - Whole-script confusable detection (entire domain in a script
    that mimics Latin)
"""

from __future__ import annotations

import re
import unicodedata
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.engines.url.brands import check_idn_homograph, load_brands
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

# Scripts that can be whole-script confusable with Latin
_CONFUSABLE_SCRIPTS = frozenset({
    "CYRILLIC", "GREEK", "ARMENIAN", "GEORGIAN", "LATIN",
    "ETHIOPIC", "CHEROKEE",
})

_PUNYCODE_RE = re.compile(r"\bxn--[a-z0-9-]+\b", re.IGNORECASE)


@register_detector
class IDNHomographDetector(BaseDetector):
    """Detects IDN homograph attacks where Unicode characters that visually
    resemble ASCII letters are used to impersonate legitimate domains.

    Example: 'paypal.com' (Cyrillic look-alike) vs 'paypal.com' (Latin)
    """

    detector_id = "d14_idn_homograph"
    name = "IDN/Homograph Attack"
    domain = "URL & Domain Security"
    domain_id = "d2"
    accepted_artifact_types = [
        ArtifactType.URL,
        ArtifactType.EMAIL,
        ArtifactType.SMS,
        ArtifactType.WEBPAGE,
    ]
    required_engines = ["url"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        url = artifact.normalized_url or artifact.raw_content or ""
        if not url:
            return self._no_hit(artifact)

        try:
            parsed = urlparse(url)
            netloc = parsed.netloc or ""
            hostname = (parsed.hostname or "").lower()
        except Exception as exc:
            return self._error(artifact, str(exc))

        evidence: list[Evidence] = []
        score = 0.0

        # ── 1. Punycode label detection ────────────────────────────────────────
        punycode_labels = _PUNYCODE_RE.findall(netloc)
        if punycode_labels:
            # Decode each punycode label
            decoded_labels: list[str] = []
            for label in punycode_labels:
                try:
                    decoded = label.encode("ascii").decode("idna")
                    decoded_labels.append(f"{label} → {decoded}")
                except Exception:
                    decoded_labels.append(label)

            evidence.append(Evidence(
                source_engine="url",
                severity=EvidenceSeverity.HIGH,
                description=(
                    f"Domain contains {len(punycode_labels)} Punycode label(s): "
                    + ", ".join(decoded_labels[:3])
                ),
                rule_id="punycode_labels",
                matched_text=netloc,
            ))
            score = max(score, 0.5)

            # ── 2. Brand skeleton comparison ──────────────────────────────────
            brand_hits = check_idn_homograph(netloc, hostname)
            for hit in brand_hits:
                evidence.append(Evidence(
                    source_engine="url",
                    severity=EvidenceSeverity.CRITICAL,
                    description=hit.evidence_text,
                    matched_text=hit.matched_term,
                    rule_id=f"idn_skeleton_{hit.brand_key}",
                    metadata={
                        "brand": hit.brand_key,
                        "display_name": hit.display_name,
                        "decoded": hit.matched_against,
                    },
                ))
                score = max(score, 0.90)

        # ── 3. Mixed-script detection (no Punycode needed) ────────────────────
        if hostname:
            mixed_result = _detect_mixed_scripts(hostname)
            if mixed_result:
                scripts, example = mixed_result
                evidence.append(Evidence(
                    source_engine="url",
                    severity=EvidenceSeverity.HIGH,
                    description=(
                        f"Domain '{hostname}' contains mixed Unicode scripts "
                        f"({', '.join(scripts)}) — may be a visual lookalike attack. "
                        f"Example character: '{example}'"
                    ),
                    rule_id="mixed_script",
                    matched_text=hostname,
                ))
                score = max(score, 0.65)

        # ── 4. Whole-script confusable (Cyrillic/Greek domain) ────────────────
        if hostname:
            whole = _detect_whole_script_confusable(hostname)
            if whole:
                script, _ = whole
                evidence.append(Evidence(
                    source_engine="url",
                    severity=EvidenceSeverity.HIGH,
                    description=(
                        f"Domain appears to be entirely in {script} script but "
                        f"visually resembles Latin characters — potential homograph attack"
                    ),
                    rule_id="whole_script_confusable",
                    matched_text=hostname,
                ))
                score = max(score, 0.55)

                # Check brand list using skeleton comparison
                from app.engines.url.brands import build_unicode_skeleton
                skeleton = build_unicode_skeleton(hostname)
                brands = load_brands()
                for brand in brands:
                    for bd in brand.domains:
                        bd_skeleton = build_unicode_skeleton(bd.split(".")[0])
                        if skeleton == bd_skeleton and hostname != bd.split(".")[0]:
                            evidence.append(Evidence(
                                source_engine="url",
                                severity=EvidenceSeverity.CRITICAL,
                                description=(
                                    f"Domain '{hostname}' (skeleton: '{skeleton}') is visually "
                                    f"identical to '{bd}' ({brand.display_name})"
                                ),
                                rule_id=f"skeleton_brand_{brand.brand_key}",
                                matched_text=hostname,
                            ))
                            score = max(score, 0.95)
                            break

        if not evidence:
            return self._no_hit(artifact)

        verdict = (
            Verdict.MALICIOUS if score >= 0.75
            else Verdict.LIKELY_MALICIOUS if score >= 0.55
            else Verdict.SUSPICIOUS if score >= 0.35
            else Verdict.SAFE
        )

        return DetectionResult(
            detector_id=self.detector_id,
            name=self.name,
            domain=self.domain,
            domain_id=self.domain_id,
            score=round(score, 4),
            verdict=verdict,
            confidence=round(min(0.95, score + 0.05), 3),
            evidence=evidence,
            signals_used=["url.has_punycode", "url.domain"],
        )

    def _no_hit(self, artifact: Artifact) -> DetectionResult:
        return DetectionResult(
            detector_id=self.detector_id,
            name=self.name,
            domain=self.domain,
            domain_id=self.domain_id,
            score=0.0,
            verdict=Verdict.SAFE,
            confidence=0.8,
            evidence=[],
            signals_used=["url.has_punycode"],
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


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_script(char: str) -> str:
    """Return the Unicode script name for *char* (approximation via category)."""
    # Use character name to guess script
    try:
        name = unicodedata.name(char, "")
        # Extract script from name prefix
        if "CYRILLIC" in name:
            return "CYRILLIC"
        if "GREEK" in name:
            return "GREEK"
        if "ARMENIAN" in name:
            return "ARMENIAN"
        if "GEORGIAN" in name:
            return "GEORGIAN"
        if "ARABIC" in name:
            return "ARABIC"
        if "HEBREW" in name:
            return "HEBREW"
        if "LATIN" in name or unicodedata.category(char).startswith("L"):
            return "LATIN"
    except Exception:
        pass
    return "UNKNOWN"


def _detect_mixed_scripts(domain: str) -> tuple[set[str], str] | None:
    """Return (set_of_scripts, example_char) if domain has mixed scripts."""
    scripts: dict[str, str] = {}  # script → first char
    for char in domain:
        if char in ".-_":
            continue
        if ord(char) < 128:
            scripts.setdefault("LATIN", char)
        else:
            script = _get_script(char)
            if script not in ("UNKNOWN", "LATIN"):
                scripts[script] = char

    # Mixed if we have LATIN + another script
    if "LATIN" in scripts and len(scripts) >= 2:
        non_latin = {s: c for s, c in scripts.items() if s != "LATIN"}
        if non_latin:
            example_char = next(iter(non_latin.values()))
            return set(scripts.keys()), example_char

    return None


def _detect_whole_script_confusable(domain: str) -> tuple[str, str] | None:
    """Return (script, example_char) if domain is entirely in a non-Latin
    confusable script (e.g. entirely Cyrillic).
    """
    scripts: dict[str, str] = {}
    for char in domain:
        if char in ".-_" or ord(char) < 128:
            continue
        script = _get_script(char)
        if script not in ("UNKNOWN",):
            scripts[script] = char

    if len(scripts) == 1:
        script, example = next(iter(scripts.items()))
        if script in _CONFUSABLE_SCRIPTS - {"LATIN"}:
            return script, example

    return None
