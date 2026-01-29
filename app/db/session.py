from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine, _SessionLocal
    if _engine is None:
        # NOTE:
        # - DATABASE_URL points to the Postgres 15 service inside Docker compose network.
        # - Example: postgresql+psycopg://hotel_user:...@postgres:5432/hotel
        # - We do NOT publish Postgres to the host.
        _engine = create_engine(
            settings.database_url,
            pool_pre_ping=True,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_recycle=settings.db_pool_recycle_seconds,
            future=True,
        )
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, expire_on_commit=False)
    return _engine


def get_sessionmaker() -> sessionmaker[Session]:
    if _SessionLocal is None:
        get_engine()
    assert _SessionLocal is not None
    return _SessionLocal


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that provides a transactional Session.

    We keep it simple: one Session per request; commit/rollback controlled by the caller.
    Most endpoints will use explicit commit at the end of successful writes.
    """

    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def SessionLocal() -> Session:
    """Legacy alias returning a new Session instance."""

    SessionCls = get_sessionmaker()
    return SessionCls()
