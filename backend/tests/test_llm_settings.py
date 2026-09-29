"""Tests for the runtime-switchable LLM model settings."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(  # type: ignore[arg-type]
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="gemini",
        llm_api_key="secret",
        llm_model="gemini-3.8-flash",
    )
    app = create_app(settings=settings)
    with TestClient(app) as test_client:
        yield test_client


def test_llm_settings_default_has_no_override(client: TestClient) -> None:
    body = client.get("/api/v1/settings/llm").json()
    assert body["provider"] == "gemini"
    assert body["overridden"] is False
    assert body["model"] == body["env_model"] == "gemini-3.8-flash"
    assert body["configured"] is True  # provider + api key set


def test_llm_model_override_roundtrip(client: TestClient) -> None:
    updated = client.put(
        "/api/v1/settings/llm", json={"model": "gemini-flash-latest"}
    ).json()
    assert updated["overridden"] is True
    assert updated["model"] == "gemini-flash-latest"
    assert updated["env_model"] == "gemini-3.8-flash"  # env default unchanged

    # Persisted across requests.
    assert client.get("/api/v1/settings/llm").json()["model"] == "gemini-flash-latest"


def test_llm_model_override_can_be_cleared(client: TestClient) -> None:
    client.put("/api/v1/settings/llm", json={"model": "gemini-flash-latest"})
    cleared = client.put("/api/v1/settings/llm", json={"model": ""}).json()
    assert cleared["overridden"] is False
    assert cleared["model"] == cleared["env_model"] == "gemini-3.8-flash"
