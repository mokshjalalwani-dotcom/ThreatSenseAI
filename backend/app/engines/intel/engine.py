"""
Threat Intelligence Provider — stub for Stage 9.

Full implementation: Google Safe Browsing, VirusTotal, URLhaus, OpenPhish
feed (local DB sync), AbuseIPDB, DNSBL; per-provider rate limiting, circuit
breaker, offline mode with local feeds.
"""

from __future__ import annotations

import logging

from app.schemas.schemas import IntelSignals

logger = logging.getLogger(__name__)


class IntelProvider:
    """Shared threat-intelligence reputation lookup provider.

    Stage 1: stub — returns empty IntelSignals in offline mode.
    Stage 9: full multi-provider lookup with caching and circuit breaker.
    """

    async def lookup(self, indicator: str) -> IntelSignals:
        """Look up a URL, domain, or file hash against intel providers.

        Args:
            indicator: A URL, domain name, or SHA-256 file hash string.

        Returns:
            IntelSignals with aggregated provider hits and metadata.
        """
        logger.debug("IntelProvider.lookup called (stub) for indicator=%r", indicator[:80])
        return IntelSignals(offline_mode=True)
