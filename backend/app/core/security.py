"""
Security dependencies for FastAPI routes.
"""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.core.config import settings

# Dependency that reads the API key from the header
api_key_header = APIKeyHeader(name=settings.API_KEY_HEADER, auto_error=False)


async def verify_api_key(
    api_key: Annotated[str | None, Security(api_key_header)]
) -> str | None:
    """Validate the API key if authentication is enabled.

    If settings.API_KEY is empty, authentication is disabled (dev mode).
    Otherwise, the client must provide a matching key in the configured header.
    """
    if not settings.API_KEY:
        return None  # Auth disabled

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing API Key",
        )

    # Use constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(api_key, settings.API_KEY):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API Key",
        )

    return api_key
