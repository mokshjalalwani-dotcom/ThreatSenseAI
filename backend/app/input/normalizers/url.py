"""URL input normalizer."""

from __future__ import annotations

import logging
from urllib.parse import parse_qs, unquote, urlparse, urlunparse

import tldextract

from app.input.normalizers.base import BaseNormalizer
from app.input.normalizers.utils import extract_urls
from app.schemas.schemas import Artifact, ArtifactType

logger = logging.getLogger(__name__)

# tldextract instance (cached — avoids repeated IANA list fetches)
_TLD = tldextract.TLDExtract(cache_dir=None)


class URLNormalizer(BaseNormalizer):
    """Canonical URL normalizer.

    Steps:
      1. Strip leading/trailing whitespace and BOM characters.
      2. Parse with urllib.parse.
      3. Lowercase the scheme and host.
      4. Percent-decode path (then re-encode safely).
      5. Extract TLD / domain / subdomain via tldextract.
      6. Scan raw_content for any embedded URLs (e.g. open redirectors).
      7. Store parsed components in metadata.
    """

    artifact_type = ArtifactType.URL

    def normalize(self, raw: str | bytes, **kwargs: object) -> Artifact:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")

        url = raw.strip().lstrip("\ufeff")  # Strip BOM

        try:
            parsed = urlparse(url)
            scheme = (parsed.scheme or "https").lower()
            netloc = (parsed.netloc or "").lower()
            path = unquote(parsed.path)

            # Reconstruct canonical form
            canonical = urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))

            ext = _TLD(netloc)
            parsed_qs = parse_qs(parsed.query)

            # Look for embedded/redirect URLs in query params
            embedded_urls: list[str] = []
            for values in parsed_qs.values():
                for v in values:
                    if v.startswith(("http://", "https://")):
                        embedded_urls.append(v)
            embedded_urls.extend(extract_urls(path))

            return Artifact(
                type=ArtifactType.URL,
                raw_content=url,
                normalized_url=canonical,
                extracted_urls=embedded_urls,
                metadata={
                    "scheme": scheme,
                    "netloc": netloc,
                    "domain": ext.domain,
                    "subdomain": ext.subdomain,
                    "tld": ext.suffix,
                    "registered_domain": ext.registered_domain,
                    "path": path,
                    "query": parsed.query,
                    "fragment": parsed.fragment,
                    "query_params": {k: v[0] if len(v) == 1 else v for k, v in parsed_qs.items()},
                    "is_ip_host": _is_ip(netloc),
                },
            )
        except Exception as exc:
            logger.warning("URLNormalizer failed for %r: %s", url[:80], exc)
            return Artifact(
                type=ArtifactType.URL,
                raw_content=url,
                metadata={"parse_error": str(exc)},
            )


def _is_ip(netloc: str) -> bool:
    """Return True if *netloc* looks like a bare IP (v4 or v6)."""
    import ipaddress

    host = netloc.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
