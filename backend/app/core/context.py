"""
THREAT-SENSE AI — AnalysisContext.

The AnalysisContext is the shared state for one analysis run.  It:

1.  Holds the Artifact being analysed.
2.  Holds references to all engine instances.
3.  Lazily computes and caches each engine's output so that even when 9
    detectors in Domain 1 all call ``get_nlp_signals()``, the NLP backend
    runs EXACTLY ONCE per artifact.
4.  Tracks per-engine invocation counts (used by the unit tests to prove
    the caching guarantee).
5.  Records which engines failed so the aggregator can lower confidence and
    report skipped components.

Thread/async safety
-------------------
Each ``_get_or_compute()`` call uses a per-key ``asyncio.Lock`` (double-
checked locking pattern) to prevent concurrent coroutines from computing
the same engine result twice on the first call.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Callable, Coroutine
from typing import Any

from app.schemas.schemas import (
    Artifact,
    EmailSignals,
    EngineSignals,
    IntelSignals,
    NLPSignals,
    URLSignals,
    WebSignals,
)

logger = logging.getLogger(__name__)


class AnalysisContext:
    """Per-artifact shared engine cache.

    Args:
        artifact:       The artifact being analysed.
        nlp_engine:     Optional NLPEngine instance.
        url_engine:     Optional URLEngine instance.
        web_engine:     Optional WebEngine instance.
        email_engine:   Optional EmailEngine instance.
        media_engine:   Optional MediaEngine instance.
        intel_provider: Optional IntelProvider instance.
    """

    def __init__(
        self,
        artifact: Artifact,
        nlp_engine: Any | None = None,
        url_engine: Any | None = None,
        web_engine: Any | None = None,
        email_engine: Any | None = None,
        media_engine: Any | None = None,
        intel_provider: Any | None = None,
    ) -> None:
        self._artifact = artifact
        self._nlp_engine = nlp_engine
        self._url_engine = url_engine
        self._web_engine = web_engine
        self._email_engine = email_engine
        self._media_engine = media_engine
        self._intel_provider = intel_provider

        # Cached results: engine_key → signal object
        self._cache: dict[str, Any] = {}
        # Invocation counter: engine_key → number of times the backend was called
        # (always 0 or 1 for a correctly-working cache)
        self._call_counts: dict[str, int] = defaultdict(int)
        # Per-key locks for double-checked locking
        self._locks: dict[str, asyncio.Lock] = {}
        # Engines that failed (key → error message)
        self._failures: dict[str, str] = {}

    # ── Public artifact access ────────────────────────────────────────────────

    @property
    def artifact(self) -> Artifact:
        """The artifact under analysis."""
        return self._artifact

    # ── Engine accessors (lazy, cached) ──────────────────────────────────────

    async def get_nlp_signals(self) -> NLPSignals:
        """Return NLP signals for the artifact's text content (cached)."""
        return await self._get_or_compute("nlp", self._compute_nlp)

    async def get_url_signals(self, url: str | None = None) -> URLSignals:
        """Return URL feature signals (cached per-artifact URL)."""
        key = f"url:{url or self._artifact.raw_content}"
        return await self._get_or_compute(key, lambda: self._compute_url(url))

    async def get_web_signals(self) -> WebSignals:
        """Return DOM/HTML signals (cached)."""
        return await self._get_or_compute("web", self._compute_web)

    async def get_email_signals(self) -> EmailSignals:
        """Return email header/auth signals (cached)."""
        return await self._get_or_compute("email", self._compute_email)

    async def get_intel_signals(self, indicator: str | None = None) -> IntelSignals:
        """Return threat-intel hits (cached per indicator)."""
        key = f"intel:{indicator or self._artifact.raw_content}"
        return await self._get_or_compute(key, lambda: self._compute_intel(indicator))

    async def get_media_qr_payloads(self) -> list[str]:
        """Return decoded QR payloads (cached)."""
        return await self._get_or_compute("media:qr", self._compute_media_qr)

    async def get_media_ocr_text(self) -> str:
        """Return extracted text from image (cached)."""
        return await self._get_or_compute("media:ocr", self._compute_media_ocr)

    # ── Diagnostics ──────────────────────────────────────────────────────────

    def get_engine_call_count(self, engine_key: str) -> int:
        """Return how many times an engine's backend was actually invoked.

        A correctly-working cache will always return 0 (not run) or 1 (run
        once).  Values > 1 indicate a caching bug.
        """
        return self._call_counts.get(engine_key, 0)

    def get_failures(self) -> dict[str, str]:
        """Return {engine_key: error_message} for engines that failed."""
        return dict(self._failures)

    def get_engine_signals_snapshot(self) -> EngineSignals:
        """Build an EngineSignals object from whatever is currently cached."""
        return EngineSignals(
            nlp=self._cache.get("nlp"),
            url=next(
                (v for k, v in self._cache.items() if k.startswith("url:") and isinstance(v, URLSignals)),
                self._cache.get("url"),
            ),
            web=self._cache.get("web"),
            email=self._cache.get("email"),
            intel=next(
                (v for k, v in self._cache.items() if k.startswith("intel:") and isinstance(v, IntelSignals)),
                None,
            ),
        )

    # ── Core caching primitive ────────────────────────────────────────────────

    async def _get_or_compute(
        self,
        key: str,
        compute_fn: Callable[[], Coroutine[Any, Any, Any]],
    ) -> Any:
        """Return a cached value, computing it at most once (thread-safe)."""
        if key in self._cache:
            return self._cache[key]

        # Initialise lock on first access (safe outside async critical section)
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()

        async with self._locks[key]:
            # Double-check after acquiring the lock
            if key in self._cache:
                return self._cache[key]

            self._call_counts[key] += 1
            try:
                result = await compute_fn()
            except Exception as exc:
                error_msg = f"{type(exc).__name__}: {exc}"
                logger.error("Engine %r failed: %s", key, error_msg)
                self._failures[key] = error_msg
                # Return a safe empty default so callers don't crash
                result = self._empty_default(key)

            self._cache[key] = result
            return result

    # ── Private compute helpers (stubs; filled in by later stages) ────────────

    async def _compute_nlp(self) -> NLPSignals:
        if self._nlp_engine is None:
            return NLPSignals()
        text = self._artifact.raw_content or ""
        return await self._nlp_engine.analyze(text)

    async def _compute_url(self, url: str | None) -> URLSignals:
        if self._url_engine is None:
            return URLSignals()
        target = url or self._artifact.raw_content
        return await self._url_engine.analyze(target)

    async def _compute_web(self) -> WebSignals:
        if self._web_engine is None:
            return WebSignals()
        return await self._web_engine.analyze(self._artifact)

    async def _compute_email(self) -> EmailSignals:
        if self._email_engine is None:
            return EmailSignals()
        return await self._email_engine.analyze(self._artifact)

    async def _compute_intel(self, indicator: str | None) -> IntelSignals:
        if self._intel_provider is None:
            return IntelSignals(offline_mode=True)
        target = indicator or self._artifact.raw_content
        return await self._intel_provider.lookup(target)

    async def _compute_media_qr(self) -> list[str]:
        if self._media_engine is None:
            return []
        return await self._media_engine.decode_qr(self._artifact)

    async def _compute_media_ocr(self) -> str:
        if self._media_engine is None:
            return ""
        return await self._media_engine.extract_text_ocr(self._artifact)

    @staticmethod
    def _empty_default(key: str) -> Any:
        """Return a typed empty default for a given engine key on failure."""
        if key == "nlp":
            return NLPSignals()
        if key.startswith("url:") or key == "url":
            return URLSignals()
        if key == "web":
            return WebSignals()
        if key == "email":
            return EmailSignals()
        if key.startswith("intel:"):
            return IntelSignals(offline_mode=True)
        return None
