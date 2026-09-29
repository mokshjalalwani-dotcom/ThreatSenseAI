"""
Structured logging configuration for THREAT-SENSE AI.

Call configure_logging() once at application startup.  After that, every
module gets a properly formatted, level-filtered logger via:
    import logging
    logger = logging.getLogger(__name__)
"""

from __future__ import annotations

import logging
import sys


def configure_logging(level: str = "INFO") -> None:
    """Configure root logger with structured output.

    Args:
        level: A Python logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)-8s %(name)-40s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    # Remove any existing handlers to avoid duplicates on hot-reload
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(numeric_level)

    # Suppress noisy third-party loggers
    for noisy in ("uvicorn.access", "sqlalchemy.engine", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
