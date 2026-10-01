"""Tests for the SCM integration management API (connect/list/import/delete).

Uses a fake provider factory (no network) and asserts the access token is never
returned by the API and integrations require an encryption key.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import services.integration_service as integration_service
from core.config import Settings
from main import create_app
from services.scm.fake import FakeSCMProvider, make_repo


@pytest.fixture
def fake_factory(monkeypatch: pytest.MonkeyPatch) -> FakeSCMProvider:
    """Patch the service's provider factory to return a preloaded fake provider."""
    provider = FakeSCMProvider()
    provider.add_repo(make_repo("acme", "web"))
    provider.add_repo(make_repo("acme", "api"))

    def factory(name: str, token: str, settings: Settings) -> FakeSCMProvider:
        return provider

    monkeypatch.setattr(integration_service, "provider_factory", factory)
    return provider


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
        integration_encryption_key=Fernet.generate_key().decode(),
    )
    with TestClient(create_app(settings=settings)) as test_client:
        yield test_client


@pytest.fixture
def client_no_key(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'nokey.db'}",
        workspace_root=str(tmp_path / "ws2"),
        llm_provider="none",
        integration_encryption_key="",
    )
    with TestClient(create_app(settings=settings)) as test_client:
        yield test_client


def test_connect_requires_encryption_key(
    client_no_key: TestClient, fake_factory: FakeSCMProvider
) -> None:
    resp = client_no_key.post(
        "/api/v1/integrations", json={"provider": "github", "token": "ghp_x"}
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "integrations_disabled"


def test_connect_and_list_never_leaks_token(
    client: TestClient, fake_factory: FakeSCMProvider
) -> None:
    resp = client.post(
        "/api/v1/integrations",
        json={"provider": "github", "token": "ghp_supersecret", "name": "acme-gh"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["provider"] == "github"
    assert body["status"] == "connected"
    # The token must never be present in any response field.
    assert "token" not in body
    assert "ghp_supersecret" not in resp.text

    listed = client.get("/api/v1/integrations").json()
    assert listed["total"] == 1
    assert "ghp_supersecret" not in str(listed)


def test_connect_rejects_unknown_provider(
    client: TestClient, fake_factory: FakeSCMProvider
) -> None:
    resp = client.post(
        "/api/v1/integrations", json={"provider": "bitbucket", "token": "x"}
    )
    assert resp.status_code == 422


def test_list_remote_and_import_repository(
    client: TestClient, fake_factory: FakeSCMProvider
) -> None:
    integration_id = client.post(
        "/api/v1/integrations", json={"provider": "github", "token": "t"}
    ).json()["id"]

    remote = client.get(f"/api/v1/integrations/{integration_id}/repositories").json()
    assert remote["total"] == 2
    assert {r["full_name"] for r in remote["items"]} == {"acme/web", "acme/api"}

    imported = client.post(
        f"/api/v1/integrations/{integration_id}/repositories/import",
        json={"owner": "acme", "name": "web"},
    )
    assert imported.status_code == 201, imported.text
    assert imported.json()["full_name"] == "acme/web"

    # Importing the same repo again is idempotent (no duplicate row).
    client.post(
        f"/api/v1/integrations/{integration_id}/repositories/import",
        json={"owner": "acme", "name": "web"},
    )
    tracked = client.get("/api/v1/integrations/repositories").json()
    assert tracked["total"] == 1


def test_delete_integration(client: TestClient, fake_factory: FakeSCMProvider) -> None:
    integration_id = client.post(
        "/api/v1/integrations", json={"provider": "github", "token": "t"}
    ).json()["id"]
    assert client.delete(f"/api/v1/integrations/{integration_id}").status_code == 204
    assert client.get("/api/v1/integrations").json()["total"] == 0
    assert client.get(f"/api/v1/integrations/{integration_id}").status_code == 404
