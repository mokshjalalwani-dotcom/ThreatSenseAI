"""Webpage input normalizer.

Accepts:
  a) Pre-fetched HTML (string or bytes) — used when SafeFetcher already ran.
  b) A FetchResult object — preferred path when the caller passes the result
     of ``SafeFetcher.fetch(url)`` so the redirect chain is also recorded.
"""

from __future__ import annotations

import logging

from app.input.normalizers.base import BaseNormalizer
from app.input.normalizers.utils import extract_urls
from app.schemas.schemas import Artifact, ArtifactType, FetchResult

logger = logging.getLogger(__name__)


class WebpageNormalizer(BaseNormalizer):
    """Normalizer for HTML webpage content.

    Extracts all href/src/action URLs from HTML and stores the raw HTML
    in raw_content for later DOM analysis by the WebEngine.
    """

    artifact_type = ArtifactType.WEBPAGE

    def normalize(  # type: ignore[override]
        self,
        raw: str | bytes | FetchResult,
        **kwargs: object,
    ) -> Artifact:
        """Normalise webpage content.

        Args:
            raw:           HTML string, bytes, or a FetchResult.
            source_url:    (kwarg) The URL the page was fetched from.
            redirect_chain:(kwarg) List of URLs traversed (from FetchResult).
        """
        redirect_chain: list[str] = []
        source_url: str = str(kwargs.get("source_url", ""))
        status_code: int = 0

        if isinstance(raw, FetchResult):
            source_url = raw.final_url or source_url
            redirect_chain = raw.redirect_chain
            status_code = raw.status_code
            html_bytes = raw.body
            html = html_bytes.decode("utf-8", errors="replace")
        elif isinstance(raw, bytes):
            html = raw.decode("utf-8", errors="replace")
        else:
            html = raw

        # Extract all linked URLs from HTML attributes
        extracted_urls = _extract_all_urls_from_html(html)
        # Also extract plain-text URLs in the visible content
        extracted_urls.extend(extract_urls(html))
        # Deduplicate
        seen: set[str] = set()
        deduped: list[str] = []
        for u in extracted_urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)

        page_title = _extract_title(html)

        return Artifact(
            type=ArtifactType.WEBPAGE,
            raw_content=html,
            normalized_url=source_url,
            extracted_urls=deduped,
            metadata={
                "source_url": source_url,
                "redirect_chain": redirect_chain,
                "status_code": status_code,
                "page_title": page_title,
                "html_length": len(html),
            },
        )


def _extract_all_urls_from_html(html: str) -> list[str]:
    """Extract href, src, and action attribute URLs from raw HTML."""
    import re

    return re.findall(
        r'(?:href|src|action|data-url)=["\']?(https?://[^"\'\s>]+)',
        html,
        re.IGNORECASE,
    )


def _extract_title(html: str) -> str | None:
    """Extract <title> text from HTML (lightweight regex, no BS4 needed here)."""
    import re

    match = re.search(r"<title[^>]*>([^<]{0,200})</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else None
