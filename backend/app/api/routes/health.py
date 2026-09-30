"""GET /health — liveness and configuration check."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.registry import get_all_detectors
from app.db.session import get_db
from app.schemas.schemas import HealthResponse

router = APIRouter()

# Record startup time so we can report uptime
_START_TIME = time.monotonic()


@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health(db: AsyncSession = Depends(get_db)) -> HealthResponse:
    """Return service health and configuration summary.

    Performs a simple DB ping to verify database connectivity.
    """
    db_status = "error"
    try:
        await db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:
        pass

    return HealthResponse(
        status="ok" if db_status == "connected" else "degraded",
        version=settings.APP_VERSION,
        nlp_backend=settings.NLP_BACKEND.value,
        database=db_status,
        detector_count=len(get_all_detectors()),
        uptime_seconds=round(time.monotonic() - _START_TIME, 1),
    )
