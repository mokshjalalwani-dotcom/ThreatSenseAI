"""
URL/Domain Engine — Stage 3 implementation.

Responsibilities:
  1. Run feature extraction (features.py) — always fast, no network.
  2. Run inference via model.py (XGBoost or rule-based fallback).
  3. Return a URLSignals with risk_score and SHAP explanations.
  4. Optionally enrich with network features (disabled by default).

One instance shared across all detectors per artifact via AnalysisContext.
"""

from __future__ import annotations

import logging
import time

from app.engines.url.features import URLFeatures, extract_features
from app.engines.url.model import predict_proba
from app.schemas.schemas import Artifact, URLSignals

logger = logging.getLogger(__name__)


class URLEngine:
    """URL/Domain feature extraction and risk-scoring engine.

    Calling ``analyze(url)`` on the same URL multiple times within one
    AnalysisContext is idempotent (the context caches the result).
    """

    async def analyze(self, url: str) -> URLSignals:
        """Extract features and produce a URLSignals for *url*.

        Args:
            url: Raw URL string to analyse.

        Returns:
            Fully populated URLSignals including risk_score and shap_top_features.
        """
        t0 = time.perf_counter()
        url = (url or "").strip()
        if not url:
            return URLSignals(url=url)

        feats: URLFeatures = extract_features(url)
        vector = feats.to_vector()
        risk_score, shap_features = predict_proba(vector)

        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.debug(
            "URLEngine.analyze: url=%r score=%.3f elapsed=%.1fms",
            url[:80], risk_score, elapsed_ms,
        )

        return URLSignals(
            url=url,
            domain=feats.domain,
            tld=feats.tld,
            subdomain=feats.subdomain,
            scheme=feats.scheme,
            is_ip_host=feats.is_ip_host > 0.5,
            is_https=feats.is_https > 0.5,
            url_length=feats.url_length,
            domain_length=feats.domain_length,
            subdomain_count=feats.subdomain_count,
            digit_count=feats.digit_count,
            special_char_count=feats.special_char_count,
            entropy=feats.entropy,
            param_count=feats.param_count,
            path_depth=feats.path_depth,
            has_punycode=feats.has_punycode > 0.5,
            suspicious_tokens=_get_suspicious_tokens(url),
            risk_score=round(risk_score, 4),
            shap_top_features=shap_features,
            redirect_chain=[],  # Populated by D12 via SafeFetcher
        )

    async def analyze_artifact(self, artifact: Artifact) -> URLSignals:
        """Convenience wrapper for URL artifacts."""
        url = artifact.normalized_url or artifact.raw_content
        return await self.analyze(url)


def _get_suspicious_tokens(url: str) -> list[str]:
    """Return the list of suspicious token strings found in *url*."""
    from app.engines.url.features import _SUSPICIOUS_TOKENS

    url_lower = url.lower()
    return [t for t in _SUSPICIOUS_TOKENS if t in url_lower]
