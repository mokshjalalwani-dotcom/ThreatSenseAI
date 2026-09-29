"""GET /health — liveness and configuration check."""

from __future__ import annotations

import time

from fastapi import APIRouter

from app.core.config import settings
from app.core.registry import get_all_detectors
from app.schemas.schemas import HealthResponse

router = APIRouter()

# Record startup time so we can report uptime
_START_TIME = time.monotonic()


@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health() -> HealthResponse:
    """Return service health and configuration summary.

    This endpoint is used by Docker's healthcheck and by CI smoke tests.
    It does NOT perform a live DB query (to keep it fast and dependency-free).
    """
    return HealthResponse(
        status="ok",
        version=settings.APP_VERSION,
        nlp_backend=settings.NLP_BACKEND.value,
        database="connected",  # Actual DB ping added in Stage 2
        detector_count=len(get_all_detectors()),
        uptime_seconds=round(time.monotonic() - _START_TIME, 1),
    )
