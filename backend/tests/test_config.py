"""Tests for configuration parsing and derived connection URLs."""

from __future__ import annotations

from core.config import Settings


def test_cors_origins_are_parsed_into_a_list() -> None:
    settings = Settings(cors_origins="http://a.test, http://b.test ,")
    assert settings.cors_origins_list == ["http://a.test", "http://b.test"]


def test_database_url_is_async_postgres() -> None:
    settings = Settings(
        postgres_user="u",
        postgres_password="p",
        postgres_host="db",
        postgres_port=5432,
        postgres_db="auditor",
    )
    assert settings.database_url == "postgresql+asyncpg://u:p@db:5432/auditor"


def test_redis_url_includes_password_when_set() -> None:
    with_pw = Settings(redis_password="secret", redis_host="cache", redis_port=6379, redis_db=1)
    assert with_pw.redis_url == "redis://:secret@cache:6379/1"

    without_pw = Settings(redis_password="", redis_host="cache", redis_port=6379, redis_db=0)
    assert without_pw.redis_url == "redis://cache:6379/0"
