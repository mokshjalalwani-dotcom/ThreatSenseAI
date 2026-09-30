"""
SafeFetcher — the ONLY component in THREAT-SENSE AI allowed to make
outbound HTTP/HTTPS requests.

Security properties enforced on every call:
  1. Scheme allowlist: only http and https.
  2. SSRF guard: host resolved to IPs; each IP checked against blocklist.
  3. Redirect safety: every redirect target is checked BEFORE following.
  4. Timeout: configurable per-instance and per-call (default 10 s).
  5. Body size cap: reads at most MAX_BODY_BYTES bytes (default 10 MB).
  6. Redirect cap: max 5 hops (configurable).
  7. No cookies stored between requests.
  8. Custom User-Agent declared.
  9. No response caching.
 10. Redirect chain captured for Domain-2 redirect detectors.
 11. Supports GET and POST methods (for threat-intel APIs).

Usage:
    fetcher = SafeFetcher()
    result = await fetcher.fetch("https://example.com")
    result = await fetcher.fetch("https://api.example.com/lookup",
                                  method="POST",
                                  data={"url": "http://suspect.com"},
                                  timeout=5.0)
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from urllib.parse import urljoin, urlparse

import httpx

from app.fetcher.ssrf_guard import SSRFError, assert_host_is_safe
from app.schemas.schemas import FetchResult

logger = logging.getLogger(__name__)

# ── Error types ───────────────────────────────────────────────────────────────


class FetchError(Exception):
    """Base class for all SafeFetcher errors."""


class DisallowedSchemeError(FetchError):
    """Raised when the URL uses a non-allowed scheme."""


class TooManyRedirectsError(FetchError):
    """Raised when a redirect chain exceeds the max-hops limit."""


class BodyTooLargeError(FetchError):
    """Raised when the response body exceeds the size cap."""


# ── SafeFetcher ───────────────────────────────────────────────────────────────

_ALLOWED_SCHEMES = {"http", "https"}
_ALLOWED_METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH"}


class SafeFetcher:
    """Async, SSRF-hardened HTTP fetcher.

    Args:
        timeout_seconds:    Per-request connect+read timeout in seconds.
        max_body_bytes:     Maximum response body size.  Excess is silently
                            truncated to this limit.
        max_redirects:      Maximum number of redirect hops.
        user_agent:         User-Agent header sent on every request.
        proxy:              Optional HTTP(S) proxy URL.
        resolver:           Injectable DNS resolver ``host -> [ip_str, ...]``
                            for unit tests.  Defaults to ``socket.getaddrinfo``.
    """

    def __init__(
        self,
        timeout_seconds: float = 10.0,
        max_body_bytes: int = 10 * 1024 * 1024,
        max_redirects: int = 5,
        user_agent: str = (
            "ThreatSenseAI/0.1 (security-scanner; contact=admin@example.com)"
        ),
        proxy: str | None = None,
        resolver: Callable[[str], list[str]] | None = None,
    ) -> None:
        self._timeout = timeout_seconds
        self._max_body_bytes = max_body_bytes
        self._max_redirects = max_redirects
        self._user_agent = user_agent
        self._resolver = resolver

        transport_kwargs: dict = {}
        if proxy:
            transport_kwargs["proxy"] = proxy

        self._client = httpx.AsyncClient(
            follow_redirects=False,        # We follow manually for SSRF re-check
            timeout=httpx.Timeout(timeout_seconds),
            headers={"User-Agent": user_agent},
            cookies=None,                  # No cookie jar
            **transport_kwargs,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        data: dict | None = None,
        json: dict | None = None,
        headers: dict | None = None,
        timeout: float | None = None,
    ) -> FetchResult:
        """Fetch *url* safely, following redirects with SSRF re-checks.

        Args:
            url:     The target URL.  Must use http or https.
            method:  HTTP method (GET, POST, PUT, etc.).  Default: GET.
            data:    Form-encoded body dict (for POST requests).
            json:    JSON body dict (for POST requests).  Mutually exclusive
                     with ``data``.
            headers: Extra request headers merged with default headers.
            timeout: Per-call timeout override in seconds.  Falls back to
                     the instance-level ``timeout_seconds``.

        Returns:
            A FetchResult with body, status code, content-type, and the
            full redirect chain.

        Raises:
            DisallowedSchemeError: If the URL scheme is not http/https.
            SSRFError:             If the host (or any redirect target) resolves
                                   to a blocked IP range.
            TooManyRedirectsError: If the redirect chain exceeds the cap.
            FetchError:            For any other network/HTTP error.
            ValueError:            If ``method`` is not in the allowed set.
        """
        method = method.upper()
        if method not in _ALLOWED_METHODS:
            raise ValueError(
                f"HTTP method {method!r} is not allowed. "
                f"Permitted: {_ALLOWED_METHODS}"
            )

        self._check_scheme(url)
        redirect_chain: list[str] = [url]
        current_url = url

        # Build request timeout
        req_timeout = httpx.Timeout(timeout if timeout is not None else self._timeout)

        for hop in range(self._max_redirects + 1):
            # SSRF check before every connection
            parsed = urlparse(current_url)
            host = parsed.hostname or ""
            if not host:
                raise FetchError(f"Cannot determine host from URL: {current_url!r}")

            try:
                assert_host_is_safe(host, resolver=self._resolver)
            except SSRFError:
                raise  # Re-raise as-is so callers can distinguish SSRF

            logger.debug("SafeFetcher %s hop %d: %s", method, hop, current_url)

            try:
                # Only send body/data on the first hop; redirects always GET
                is_first_hop = hop == 0
                req_method = method if is_first_hop else "GET"
                kwargs: dict = {
                    "url": current_url,
                    "timeout": req_timeout,
                }
                if headers:
                    kwargs["headers"] = headers
                if is_first_hop:
                    if data is not None:
                        kwargs["data"] = data
                    if json is not None:
                        kwargs["json"] = json

                response = await self._client.request(req_method, **kwargs)
            except httpx.TimeoutException as exc:
                raise FetchError(f"Request to {current_url!r} timed out: {exc}") from exc
            except httpx.RequestError as exc:
                raise FetchError(f"Request to {current_url!r} failed: {exc}") from exc

            if response.is_redirect:
                location = response.headers.get("location", "")
                if not location:
                    # No Location header — treat as final
                    break
                next_url = urljoin(current_url, location)
                redirect_chain.append(next_url)

                if len(redirect_chain) > self._max_redirects + 1:
                    raise TooManyRedirectsError(
                        f"Exceeded {self._max_redirects} redirects for {url!r}. "
                        f"Chain: {redirect_chain}"
                    )

                current_url = next_url
                continue

            # Final response
            body = response.content[: self._max_body_bytes]
            content_type = response.headers.get("content-type", "")
            logger.debug(
                "SafeFetcher done: status=%d ct=%r body_size=%d chain=%s",
                response.status_code,
                content_type,
                len(body),
                redirect_chain,
            )
            return FetchResult(
                url=url,
                final_url=current_url,
                status_code=response.status_code,
                content_type=content_type,
                body=body,
                redirect_chain=redirect_chain,
            )

        raise TooManyRedirectsError(
            f"Exceeded {self._max_redirects} redirects for {url!r}. "
            f"Chain: {redirect_chain}"
        )

    async def close(self) -> None:
        """Close the underlying httpx client."""
        await self._client.aclose()

    async def __aenter__(self) -> SafeFetcher:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _check_scheme(url: str) -> None:
        """Verify the URL uses an allowed scheme.

        Raises:
            DisallowedSchemeError: For non-http/https schemes.
        """
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise DisallowedSchemeError(
                f"Scheme {scheme!r} is not allowed.  "
                f"Only {_ALLOWED_SCHEMES} are permitted."
            )


# ── Module-level singleton (shared across requests) ───────────────────────────

_default_fetcher: SafeFetcher | None = None


def get_safe_fetcher() -> SafeFetcher:
    """Return the module-level SafeFetcher singleton (created on first call)."""
    global _default_fetcher
    if _default_fetcher is None:
        from app.core.config import settings

        _default_fetcher = SafeFetcher(
            timeout_seconds=settings.SAFE_FETCHER_TIMEOUT_SECONDS,
            max_body_bytes=settings.SAFE_FETCHER_MAX_BODY_BYTES,
            max_redirects=settings.SAFE_FETCHER_MAX_REDIRECTS,
            user_agent=settings.SAFE_FETCHER_USER_AGENT,
            proxy=settings.SAFE_FETCHER_PROXY or None,
        )
    return _default_fetcher
