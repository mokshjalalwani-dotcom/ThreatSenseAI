"""
Shared pytest fixtures for THREAT-SENSE AI tests.

DB setup
--------
The API tests use a **shared in-memory SQLite DB** that is created once per
test session.  The session-scoped ``setup_db`` fixture calls
``Base.metadata.create_all`` before any test runs, so the tables exist when
the HTTPX test client hits /analyze.

We also override DATABASE_URL to use an *in-memory* SQLite so tests never
touch the dev database file.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio

# ── Point at an in-memory SQLite before any app code loads the engine ─────────
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(scope="session", autouse=True)
def import_detectors() -> None:
    """Ensure all 22 detectors are imported (triggers @register_detector)."""
    import app.detectors  # noqa: F401


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_db():
    """Create all tables in the test DB once per session."""
    from app.db.models import Base
    from app.db.session import engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    # Teardown — drop all tables (belt-and-suspenders for in-memory)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def client(setup_db):
    """Async HTTPX test client bound to the FastAPI app."""
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as c:
        yield c
