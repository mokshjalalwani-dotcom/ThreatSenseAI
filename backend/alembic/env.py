"""
Alembic environment configuration.

Supports both SQLite (development) and PostgreSQL (production).
Alembic always runs synchronously even though the app uses async SQLAlchemy;
we convert the async URL to its synchronous equivalent here.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Import models so Alembic autogenerate can see them
from app.db.models import Base  # noqa: F401
from app.core.config import settings

# Alembic Config object
config = context.config

# Set up Python logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Autogenerate target
target_metadata = Base.metadata


def get_sync_url() -> str:
    """Convert the async DATABASE_URL to a synchronous driver URL for Alembic."""
    return settings.sync_database_url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (no live DB connection)."""
    url = get_sync_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (connects to the DB)."""
    cfg = config.get_section(config.config_ini_section) or {}
    cfg["sqlalchemy.url"] = get_sync_url()

    connectable = engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
