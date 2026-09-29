"""
Intel Engine — Stage 9: Threat Intelligence Enrichment.

Free, offline-first intelligence sources (no API key required for basic use):

  1. Local blocklist (bundled): domains / IPs / hashes from public feeds
     embedded at build time in data/blocklists/*.txt.
  2. URLhaus (abuse.ch) — free, no auth: https://urlhaus-api.abuse.ch/v1/
  3. PhishTank — free, no auth via CSV snapshot (downloaded separately).

Lookup priority:
  local_blocklist → urlhaus (if network allowed) → phishtank_offline

All network calls go through SafeFetcher (SSRF guard included).
Environment:
  INTEL_OFFLINE=true  (default) — skip any live API calls.
  INTEL_OFFLINE=false           — enable URLhaus live lookup.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from app.schemas.schemas import IntelSignals

logger = logging.getLogger(__name__)

_OFFLINE = os.getenv("INTEL_OFFLINE", "true").lower() == "true"

# ── Local blocklist paths (bundled with repo) ──────────────────────────────────
_DATA_DIR = Path(__file__).parent / "data"
_DOMAIN_BLOCKLIST  = _DATA_DIR / "domains.txt"
_IP_BLOCKLIST      = _DATA_DIR / "ips.txt"
_HASH_BLOCKLIST    = _DATA_DIR / "hashes.txt"
_URL_BLOCKLIST     = _DATA_DIR / "urls.txt"

_URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"


def _load_set(path: Path) -> frozenset[str]:
    """Load a line-delimited blocklist file into a frozenset (lowercased)."""
    if not path.exists():
        return frozenset()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        return frozenset(line.strip().lower() for line in lines if line.strip() and not line.startswith("#"))
    except Exception as exc:
        logger.warning("Failed to load blocklist %s: %s", path, exc)
        return frozenset()


# Module-level caches (loaded once on first import)
_DOMAIN_SET: frozenset[str] | None = None
_IP_SET:     frozenset[str] | None = None
_HASH_SET:   frozenset[str] | None = None
_URL_SET:    frozenset[str] | None = None


def _get_sets() -> tuple[frozenset[str], frozenset[str], frozenset[str], frozenset[str]]:
    global _DOMAIN_SET, _IP_SET, _HASH_SET, _URL_SET
    if _DOMAIN_SET is None:
        _DOMAIN_SET = _load_set(_DOMAIN_BLOCKLIST)
        _IP_SET     = _load_set(_IP_BLOCKLIST)
        _HASH_SET   = _load_set(_HASH_BLOCKLIST)
        _URL_SET    = _load_set(_URL_BLOCKLIST)
        logger.info(
            "Intel blocklists loaded: %d domains, %d IPs, %d hashes, %d URLs",
            len(_DOMAIN_SET), len(_IP_SET), len(_HASH_SET), len(_URL_SET),
        )
    return _DOMAIN_SET, _IP_SET, _HASH_SET, _URL_SET


def _check_local(indicator: str) -> list[dict]:
    """Check indicator against all local blocklists. Returns list of hit dicts."""
    domains, ips, hashes, urls = _get_sets()
    hits = []
    ind_lower = indicator.lower().strip()

    if ind_lower in domains:
        hits.append({"source": "local_domains", "type": "domain",
                     "indicator": ind_lower, "threat": "blocklisted_domain"})

    if ind_lower in ips:
        hits.append({"source": "local_ips", "type": "ip",
                     "indicator": ind_lower, "threat": "blocklisted_ip"})

    if ind_lower in hashes:
        hits.append({"source": "local_hashes", "type": "hash",
                     "indicator": ind_lower, "threat": "known_malware_hash"})

    if ind_lower in urls:
        hits.append({"source": "local_urls", "type": "url",
                     "indicator": ind_lower, "threat": "blocklisted_url"})

    # Also check SHA-256 of indicator bytes
    sha256 = hashlib.sha256(indicator.encode()).hexdigest()
    if sha256 in hashes:
        hits.append({"source": "local_hashes", "type": "hash",
                     "indicator": sha256, "threat": "known_malware_hash"})

    return hits


async def _check_urlhaus(indicator: str) -> list[dict]:
    """Live URLhaus lookup (only when INTEL_OFFLINE=false)."""
    if _OFFLINE:
        return []
    try:
        from app.fetcher.safe_fetcher import SafeFetcher
        fetcher = SafeFetcher()
        result = await fetcher.fetch(
            _URLHAUS_API,
            method="POST",
            data={"url": indicator},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=5.0,
        )
        import json
        data = json.loads(result.body)
        if data.get("query_status") == "is_listed":
            return [{
                "source": "urlhaus",
                "type": "url",
                "indicator": indicator,
                "threat": data.get("threat", "malware_url"),
                "tags": data.get("tags", []),
            }]
    except Exception as exc:
        logger.debug("URLhaus lookup failed for %s: %s", indicator[:40], exc)
    return []


class IntelEngine:
    """Threat intelligence lookup engine.

    Checks local blocklists first (fast, offline), then optionally
    queries URLhaus live API when INTEL_OFFLINE=false.
    """

    async def lookup(self, indicator: str) -> IntelSignals:
        """Look up an indicator (URL, domain, IP, hash) in threat intel sources.

        Args:
            indicator: The value to check.

        Returns:
            IntelSignals with all hits and query metadata.
        """
        if not indicator:
            return IntelSignals(offline_mode=_OFFLINE)

        providers_queried: list[str] = ["local_blocklist"]
        providers_failed: list[str] = []

        # 1. Local blocklist
        hits = _check_local(indicator)

        # 2. URLhaus live (optional)
        if not _OFFLINE:
            providers_queried.append("urlhaus")
            try:
                urlhaus_hits = await _check_urlhaus(indicator)
                hits.extend(urlhaus_hits)
            except Exception as exc:
                providers_failed.append("urlhaus")
                logger.warning("URLhaus lookup exception: %s", exc)

        return IntelSignals(
            hits=hits,
            providers_queried=providers_queried,
            providers_failed=providers_failed,
            offline_mode=_OFFLINE,
        )
