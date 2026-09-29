"""Fetcher package — exports SafeFetcher and SSRF guard."""

from app.fetcher.safe_fetcher import (
    BodyTooLargeError,
    DisallowedSchemeError,
    FetchError,
    SafeFetcher,
    TooManyRedirectsError,
    get_safe_fetcher,
)
from app.fetcher.ssrf_guard import SSRFError, assert_host_is_safe

__all__ = [
    "BodyTooLargeError",
    "DisallowedSchemeError",
    "FetchError",
    "SSRFError",
    "SafeFetcher",
    "TooManyRedirectsError",
    "assert_host_is_safe",
    "get_safe_fetcher",
]
