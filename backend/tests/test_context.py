"""
Tests for AnalysisContext — proves the engine-caching guarantee.

Acceptance criteria:
  ✓ NLP backend is called EXACTLY ONCE even when get_nlp_signals() is
    called multiple times (simulating 9 Domain-1 detectors).
  ✓ Concurrent calls to get_nlp_signals() also only invoke the backend once.
  ✓ Engine failure is handled gracefully (returns empty signals, records error).
  ✓ get_engine_signals_snapshot() reflects cached state correctly.
"""

from __future__ import annotations

import asyncio

from app.core.context import AnalysisContext
from app.engines.nlp.backends.base import SignalBackend
from app.engines.nlp.engine import NLPEngine
from app.schemas.schemas import Artifact, ArtifactType, NLPSignals

# ── Helpers ───────────────────────────────────────────────────────────────────


class CountingBackend(SignalBackend):
    """A test backend that counts how many times analyze() was called."""

    def __init__(self) -> None:
        self.call_count: int = 0

    async def analyze(self, text: str) -> NLPSignals:
        self.call_count += 1
        return NLPSignals(
            backend_used="counting",
            text_length=len(text),
            urgency=0.5,  # Non-zero so we can verify results are real
        )

    @property
    def backend_name(self) -> str:
        return "counting"


class FailingBackend(SignalBackend):
    """A test backend that always raises an exception."""

    async def analyze(self, text: str) -> NLPSignals:
        raise RuntimeError("Intentional test failure")

    @property
    def backend_name(self) -> str:
        return "failing"


def _make_context(backend: SignalBackend | None = None) -> tuple[AnalysisContext, CountingBackend]:
    """Create an AnalysisContext with the given backend (default: CountingBackend)."""
    if backend is None:
        backend = CountingBackend()
    engine = NLPEngine(backend=backend)
    artifact = Artifact(
        type=ArtifactType.SMS,
        raw_content="Your account has been suspended. Click here to verify.",
    )
    ctx = AnalysisContext(artifact=artifact, nlp_engine=engine)
    return ctx, backend  # type: ignore[return-value]


# ── Tests ─────────────────────────────────────────────────────────────────────


async def test_nlp_signals_computed_once_on_sequential_calls() -> None:
    """Sequential calls to get_nlp_signals() must only invoke the backend once."""
    ctx, backend = _make_context()

    result1 = await ctx.get_nlp_signals()
    result2 = await ctx.get_nlp_signals()
    result3 = await ctx.get_nlp_signals()

    assert backend.call_count == 1, (
        f"Backend was called {backend.call_count} times — expected 1."
    )
    assert ctx.get_engine_call_count("nlp") == 1
    # Verify the cached result is the same object
    assert result1 is result2 is result3


async def test_nlp_signals_computed_once_on_concurrent_calls() -> None:
    """Concurrent coroutines calling get_nlp_signals() must only trigger one backend call."""
    ctx, backend = _make_context()

    # Simulate 9 Domain-1 detectors calling concurrently
    results = await asyncio.gather(*[ctx.get_nlp_signals() for _ in range(9)])

    assert backend.call_count == 1, (
        f"Backend was called {backend.call_count} times — expected 1 (concurrent test)."
    )
    assert ctx.get_engine_call_count("nlp") == 1
    # All results must be the same cached object
    first = results[0]
    assert all(r is first for r in results)


async def test_nlp_signals_returns_correct_data() -> None:
    """get_nlp_signals() must return the actual data from the backend."""
    ctx, _ = _make_context()
    signals = await ctx.get_nlp_signals()

    assert signals.backend_used == "counting"
    assert signals.urgency == 0.5
    assert signals.text_length > 0


async def test_engine_failure_handled_gracefully() -> None:
    """If the backend raises, the context must return empty signals, NOT crash."""
    failing_engine = NLPEngine(backend=FailingBackend())
    artifact = Artifact(type=ArtifactType.SMS, raw_content="test")
    ctx = AnalysisContext(artifact=artifact, nlp_engine=failing_engine)

    signals = await ctx.get_nlp_signals()

    # Must return a valid (zeroed) NLPSignals, not raise
    assert isinstance(signals, NLPSignals)
    assert signals.urgency == 0.0

    # Failure must be recorded
    failures = ctx.get_failures()
    assert "nlp" in failures


async def test_no_nlp_engine_returns_empty_signals() -> None:
    """When no NLP engine is provided, get_nlp_signals() returns zeroed NLPSignals."""
    artifact = Artifact(type=ArtifactType.URL, raw_content="http://example.com")
    ctx = AnalysisContext(artifact=artifact, nlp_engine=None)

    signals = await ctx.get_nlp_signals()
    assert isinstance(signals, NLPSignals)
    assert signals.urgency == 0.0
    # Backend must still be "called" once (the None-engine path)
    assert ctx.get_engine_call_count("nlp") == 1


async def test_engine_signals_snapshot_reflects_cache() -> None:
    """get_engine_signals_snapshot() must include NLPSignals after get_nlp_signals()."""
    ctx, _ = _make_context()

    # Before any call — snapshot should have no NLP
    snapshot_before = ctx.get_engine_signals_snapshot()
    assert snapshot_before.nlp is None

    await ctx.get_nlp_signals()

    # After the call — snapshot should include NLP
    snapshot_after = ctx.get_engine_signals_snapshot()
    assert snapshot_after.nlp is not None
    assert snapshot_after.nlp.urgency == 0.5


async def test_artifact_is_accessible_from_context() -> None:
    """ctx.artifact must return the original artifact."""
    artifact = Artifact(type=ArtifactType.EMAIL, raw_content="Hello world")
    ctx = AnalysisContext(artifact=artifact)
    assert ctx.artifact is artifact
    assert ctx.artifact.type == ArtifactType.EMAIL
