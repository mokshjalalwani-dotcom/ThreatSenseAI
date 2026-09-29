"""
THREAT-SENSE AI — FastAPI application entry point.

Startup sequence:
  1. configure_logging()
  2. Import all detectors → triggers @register_detector (populates registry)
  3. Create DB tables (SQLite dev) or rely on Alembic (Postgres prod)
  4. Mount API routers
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logging_config import configure_logging

# ── Logging (must be first) ───────────────────────────────────────────────────
configure_logging(settings.LOG_LEVEL)
logger = logging.getLogger(__name__)

# ── Detector registration (import triggers @register_detector) ────────────────
import app.detectors  # noqa: E402  — side-effect import

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Multi-layered cybersecurity threat detection platform. "
        "Analyses URLs, domains, emails, SMS/messages, webpages, images, "
        "QR codes and files across 22 detectors in 5 detection domains."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# ── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow any frontend origin (Vercel, etc.)
    allow_credentials=False, # Must be False when allow_origins is "*"
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
from app.api.routes.analyze import router as analyze_router  # noqa: E402
from app.api.routes.detectors import router as detectors_router  # noqa: E402
from app.api.routes.health import router as health_router  # noqa: E402

app.include_router(health_router)
app.include_router(detectors_router)
app.include_router(analyze_router)


# ── Startup / shutdown events ─────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup() -> None:
    """Create DB tables for SQLite dev; Postgres uses Alembic migrations."""
    from app.core.registry import get_all_detectors, registry_stats

    logger.info(
        "Starting %s v%s | NLP backend: %s",
        settings.APP_NAME,
        settings.APP_VERSION,
        settings.NLP_BACKEND.value,
    )

    detector_count = len(get_all_detectors())
    logger.info("Detector registry loaded: %d detectors | %s", detector_count, registry_stats())

    # Auto-create tables for SQLite (dev mode); Postgres uses alembic upgrade head
    if "sqlite" in settings.DATABASE_URL:

        from app.db.models import Base
        from app.db.session import engine

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("SQLite tables created (dev mode)")


@app.on_event("shutdown")
async def on_shutdown() -> None:
    """Clean up DB connection pool on shutdown."""
    from app.db.session import engine

    await engine.dispose()
    logger.info("%s shutdown complete.", settings.APP_NAME)
