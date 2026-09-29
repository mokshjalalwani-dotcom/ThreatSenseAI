"""Detector 12 — Malicious Redirects (Domain 2: URL & Domain Security).

Analyses redirect chains to detect:
  - Open redirectors / shortened-URL abuse
  - Cross-domain hops (legitimate.com → attacker.com)
  - HTTP→HTTPS downgrade in redirect chain
  - Final destination analysed by D10 (URL model)
  - Meta-refresh / JS redirect hints in static HTML (parsed, not executed)
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.engines.url.features import extract_features
from app.engines.url.model import predict_proba
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

# Meta-refresh and JS redirect static patterns
_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\'][^"\']*url=([^"\'\s>]+)',
    re.IGNORECASE,
)
_JS_REDIRECT_RE = re.compile(
    r'(?:window\.location(?:\.href)?\s*=\s*|location\.replace\s*\()\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


@register_detector
class MaliciousRedirectsDetector(BaseDetector):
    """Detects malicious redirect chains using SafeFetcher.

    When SafeFetcher is available (ENABLE_NETWORK_FEATURES or explicit call),
    actually follows the chain.  In offline mode (default), analyses static
    HTML for meta-refresh/JS redirect hints, and flags known shorteners.
    """

    detector_id = "d12_malicious_redirects"
    name = "Malicious Redirects"
    domain = "URL & Domain Security"
    domain_id = "d2"
    accepted_artifact_types = [ArtifactType.URL, ArtifactType.EMAIL, ArtifactType.SMS]
    required_engines = ["url", "intel"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        url = artifact.normalized_url or artifact.raw_content or ""
        if not url:
            return self._no_hit(artifact)

        feats = extract_features(url)
        evidence: list[Evidence] = []
        score = 0.0

        # ── 1. Known URL shortener ─────────────────────────────────────────────
        if feats.is_shortener:
            score = max(score, 0.4)
            evidence.append(Evidence(
                source_engine="url",
                severity=EvidenceSeverity.MEDIUM,
                description=(
                    f"URL uses a known shortener/redirector service "
                    f"('{feats.registered_domain}') — the final destination is hidden"
                ),
                rule_id="known_shortener",
                matched_text=feats.registered_domain,
            ))

        # ── 2. Open redirect parameters ────────────────────────────────────────
        if feats.has_redirect_param:
            score = max(score, 0.45)
            evidence.append(Evidence(
                source_engine="url",
                severity=EvidenceSeverity.MEDIUM,
                description=(
                    "URL contains an open-redirect parameter (url=, redirect=, next=, etc.) "
                    "that may forward users to a malicious destination"
                ),
                rule_id="redirect_param",
            ))

        # ── 3. Analyse URLSignals redirect_chain (if populated by SafeFetcher) ─
        signals = await ctx.get_url_signals(url)
        chain = signals.redirect_chain or []

        if len(chain) > 1:
            score, evidence = _analyse_chain(chain, score, evidence, feats)

        # ── 4. Static HTML meta-refresh / JS redirect (for webpage artifacts) ──
        if artifact.raw_content and artifact.type.value == "webpage":
            meta_urls = _META_REFRESH_RE.findall(artifact.raw_content)
            js_urls = _JS_REDIRECT_RE.findall(artifact.raw_content)
            all_static = meta_urls + js_urls

            if all_static:
                score = max(score, 0.35)
                evidence.append(Evidence(
                    source_engine="url",
                    severity=EvidenceSeverity.MEDIUM,
                    description=(
                        f"Page contains {len(all_static)} static redirect hint(s) "
                        f"(meta-refresh or window.location): "
                        + ", ".join(u[:60] for u in all_static[:3])
                    ),
                    rule_id="static_redirect",
                ))

            # Analyse final destination if we can extract it
            if all_static:
                dest_url = all_static[0]
                dest_feats = extract_features(dest_url)
                dest_vector = dest_feats.to_vector()
                dest_risk, _ = predict_proba(dest_vector)
                if dest_risk >= 0.45:
                    score = max(score, dest_risk * 0.8)
                    evidence.append(Evidence(
                        source_engine="url",
                        severity=EvidenceSeverity.HIGH,
                        description=(
                            f"Static redirect destination '{dest_url[:80]}' "
                            f"has a malicious URL score of {dest_risk:.2f}"
                        ),
                        rule_id="dest_url_risk",
                    ))

        if not evidence:
            return self._no_hit(artifact)

        verdict = (
            Verdict.MALICIOUS if score >= 0.75
            else Verdict.LIKELY_MALICIOUS if score >= 0.55
            else Verdict.SUSPICIOUS if score >= 0.30
            else Verdict.SAFE
        )

        return DetectionResult(
            detector_id=self.detector_id,
            name=self.name,
            domain=self.domain,
            domain_id=self.domain_id,
            score=round(score, 4),
            verdict=verdict,
            confidence=round(min(0.9, score + 0.15), 3),
            evidence=evidence,
            signals_used=["url.redirect_chain", "url.is_shortener", "url.has_redirect_param"],
        )

    def _no_hit(self, artifact: Artifact) -> DetectionResult:
        return DetectionResult(
            detector_id=self.detector_id,
            name=self.name,
            domain=self.domain,
            domain_id=self.domain_id,
            score=0.0,
            verdict=Verdict.SAFE,
            confidence=0.6,
            evidence=[],
            signals_used=["url.redirect_chain"],
        )


def _analyse_chain(
    chain: list[str],
    score: float,
    evidence: list[Evidence],
    first_feats: object,
) -> tuple[float, list[Evidence]]:
    """Analyse a resolved redirect chain for anomalies."""
    evidence = list(evidence)

    if len(chain) >= 5:
        score = max(score, 0.5)
        evidence.append(Evidence(
            source_engine="url",
            severity=EvidenceSeverity.HIGH,
            description=f"Redirect chain has {len(chain)} hops — unusually long",
            rule_id="long_chain",
        ))

    # Cross-domain hops
    domains = [urlparse(u).netloc.lower() for u in chain]
    unique_doms = list(dict.fromkeys(domains))  # preserve order, deduplicate
    if len(unique_doms) >= 3:
        score = max(score, 0.55)
        evidence.append(Evidence(
            source_engine="url",
            severity=EvidenceSeverity.HIGH,
            description=(
                f"Redirect chain crosses {len(unique_doms)} different domains: "
                + " → ".join(unique_doms[:5])
            ),
            rule_id="cross_domain_hops",
        ))

    # HTTP→HTTPS downgrade
    for i in range(len(chain) - 1):
        cur_scheme = urlparse(chain[i]).scheme.lower()
        nxt_scheme = urlparse(chain[i + 1]).scheme.lower()
        if cur_scheme == "https" and nxt_scheme == "http":
            score = max(score, 0.6)
            evidence.append(Evidence(
                source_engine="url",
                severity=EvidenceSeverity.HIGH,
                description=(
                    f"Redirect step {i + 1}→{i + 2} downgrades from HTTPS to HTTP: "
                    f"{chain[i][:60]} → {chain[i + 1][:60]}"
                ),
                rule_id="https_downgrade",
            ))

    # Final destination URL risk
    final_url = chain[-1]
    if final_url != chain[0]:
        final_feats = extract_features(final_url)
        final_vector = final_feats.to_vector()
        final_risk, _ = predict_proba(final_vector)
        if final_risk >= 0.45:
            score = max(score, final_risk)
            evidence.append(Evidence(
                source_engine="url",
                severity=EvidenceSeverity.CRITICAL,
                description=(
                    f"Final redirect destination '{final_url[:80]}' "
                    f"has malicious URL score {final_risk:.2f}"
                ),
                rule_id="final_dest_risk",
                matched_text=final_url,
            ))

    return score, evidence
