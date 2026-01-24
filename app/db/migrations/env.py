"""Alembic environment for HOTEL backend.

This file configures migrations to run both in 'offline' and 'online' mode.
It loads DATABASE_URL from environment variables (typically injected from
/etc/hotelapp/hotel.env into the backend container).

Constraints:
- PostgreSQL 15 (running in Docker Compose network)
- SQLAlchemy 2.x
- Pydantic v2 settings live in app.config, but migrations must not depend
  on application runtime side-effects.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Alembic Config object, provides access to values within alembic.ini.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import metadata from models.
from app.db.models import Base  # noqa: E402

target_metadata = Base.metadata


def _get_database_url() -> str:
    """Return DATABASE_URL.

    Expected examples:
    - postgresql+psycopg://hotel:password@postgres:5432/hotel
    - postgresql+psycopg://hotel:password@127.0.0.1:5432/hotel (dev)
    """
    url = os.environ.get("DATABASE_URL")
    if not url:
        # Backward-compatible fallback if user provides components.
        pg_user = os.environ.get("POSTGRES_USER")
        pg_password = os.environ.get("POSTGRES_PASSWORD")
        pg_db = os.environ.get("POSTGRES_DB")
        pg_host = os.environ.get("POSTGRES_HOST", "postgres")
        pg_port = os.environ.get("POSTGRES_PORT", "5432")
        if pg_user and pg_password and pg_db:
            url = f"postgresql+psycopg://{pg_user}:{pg_password}@{pg_host}:{pg_port}/{pg_db}"

    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set. Provide DATABASE_URL or POSTGRES_USER/POSTGRES_PASSWORD/POSTGRES_DB."
        )

    # Do not allow sqlite in production by mistake.
    if url.startswith("sqlite"):
        raise RuntimeError("SQLite is not supported for HOTEL. Use PostgreSQL.")

    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    In this scenario we configure the context with just a URL and not an Engine.
    """
    url = _get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        render_as_batch=False,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""

    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _get_database_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        future=True,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
