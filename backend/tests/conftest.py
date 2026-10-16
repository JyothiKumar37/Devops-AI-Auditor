"""Shared pytest fixtures for the backend test suite."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from core.config import Settings
from main import create_app


@pytest.fixture
def settings() -> Settings:
    """Isolated settings pointing at unreachable dependencies.

    The foundation's health checks are designed never to raise, so tests can run
    without a live PostgreSQL or Redis.
    """
    return Settings(
        environment="development",
        postgres_host="127.0.0.1",
        postgres_port=1,
        redis_host="127.0.0.1",
        redis_port=1,
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings=settings)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
async def mem_db() -> AsyncIterator[tuple[async_sessionmaker, Settings]]:
    """A shared in-memory SQLite DB (StaticPool) + settings for service tests.

    Uses a single pooled connection so every ``sessionmaker()`` sees the same
    in-memory schema/data, and ``create_all`` runs once with no disk fsync (fast
    and reliable regardless of the host filesystem). Phase 5 service tests use
    this instead of a file DB to avoid slow per-test schema creation.
    """
    import models  # noqa: F401 - register all tables on the metadata
    from models.base import Base

    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    settings = Settings(
        environment="development",
        llm_provider="none",
        integration_encryption_key=Fernet.generate_key().decode(),
    )
    try:
        yield sessionmaker, settings
    finally:
        await engine.dispose()
