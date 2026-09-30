"""
THREAT-SENSE AI — application configuration.

All settings are read from environment variables (and an optional .env file).
Never hard-code secrets.  Every setting has a safe default for local/test use.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class NLPBackend(StrEnum):
    """Selectable NLP signal backends."""

    RULES = "rules"
    ZEROSHOT = "zeroshot"
    FINETUNED = "finetuned"
    ENSEMBLE = "ensemble"


class Settings(BaseSettings):
    """Platform-wide settings, loaded from env / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Application ──────────────────────────────────────────────────────────
    APP_NAME: str = "THREAT-SENSE AI"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # ── Database ─────────────────────────────────────────────────────────────
    # Default: SQLite (no Docker required for dev/test)
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./threatsense.db",
        description="Async SQLAlchemy connection URL.",
    )

    # ── NLP Engine ───────────────────────────────────────────────────────────
    NLP_BACKEND: NLPBackend = Field(
        default=NLPBackend.RULES,
        description=(
            "Signal backend: rules | zeroshot | finetuned | ensemble. "
            "'finetuned' raises NotImplementedError until Stage 13."
        ),
    )

    # ── Security ─────────────────────────────────────────────────────────────
    SECRET_KEY: str = "dev-secret-key-change-in-production"
    API_KEY_HEADER: str = "X-API-Key"
    API_KEY: str = ""  # Empty = auth disabled (dev mode)
    CORS_ORIGINS: str = "https://threatsense-ui.onrender.com,http://localhost:3000,http://localhost:5173,http://127.0.0.1:5173"


    # ── SafeFetcher ──────────────────────────────────────────────────────────
    SAFE_FETCHER_TIMEOUT_SECONDS: int = 10
    SAFE_FETCHER_MAX_BODY_BYTES: int = 10 * 1024 * 1024  # 10 MB
    SAFE_FETCHER_MAX_REDIRECTS: int = 5
    SAFE_FETCHER_USER_AGENT: str = (
        "ThreatSenseAI/0.1 (security-scanner; contact=admin@example.com)"
    )
    SAFE_FETCHER_PROXY: str = ""

    # ── Upload hardening ──────────────────────────────────────────────────────
    UPLOAD_MAX_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    UPLOAD_DIR: str = "./uploads"

    # ── Threat intelligence providers ────────────────────────────────────────
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    PHISHTANK_API_KEY: str = ""

    # ── Privacy ───────────────────────────────────────────────────────────────
    SEND_URLS_TO_THIRD_PARTIES: bool = True

    # ── Redis ─────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://redis:6379/0"

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Ensure LOG_LEVEL is a valid Python logging level."""
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"LOG_LEVEL must be one of {valid}, got {v!r}")
        return upper

    @property
    def sync_database_url(self) -> str:
        """Synchronous DB URL for Alembic (strips async driver prefix)."""
        url = self.DATABASE_URL
        return (
            url.replace("sqlite+aiosqlite://", "sqlite://")
               .replace("postgresql+asyncpg://", "postgresql://")
        )


# Module-level singleton — import this everywhere
settings = Settings()
