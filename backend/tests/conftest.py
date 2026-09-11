"""Shared pytest fixtures for the backend test suite."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

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
