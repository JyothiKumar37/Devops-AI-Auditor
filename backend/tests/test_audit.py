"""Tests for audit logging: secret scrubbing + recording on sensitive actions."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import services.integration_service as integ_mod
from core.config import Settings
from main import create_app
from services.audit_service import scrub
from services.scm.fake import FakeSCMProvider, make_repo

FERNET_KEY = Fernet.generate_key().decode()


def test_scrub_redacts_secret_keys() -> None:
    cleaned = scrub(
        {
            "provider": "github",
            "access_token": "ghp_secret",
            "webhook_url": "https://hooks/abc",
            "nested": {"api_key": "k", "name": "ok"},
        }
    )
    assert cleaned is not None
    assert cleaned["provider"] == "github"
    assert cleaned["access_token"] == "***redacted***"
    assert cleaned["webhook_url"] == "***redacted***"
    assert cleaned["nested"]["api_key"] == "***redacted***"
    assert cleaned["nested"]["name"] == "ok"


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    settings = Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'audit.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
        integration_encryption_key=FERNET_KEY,
    )

    def _fake_factory(provider: str, token: str, s: Settings) -> FakeSCMProvider:
        fake = FakeSCMProvider()
        fake.add_repo(make_repo("acme", "web"))
        return fake

    monkeypatch.setattr(integ_mod, "provider_factory", _fake_factory)
    with TestClient(create_app(settings=settings)) as c:
        yield c


def test_integration_connect_is_audited(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/integrations",
        json={"provider": "github", "token": "ghp_token", "name": "acme"},
    )
    assert resp.status_code == 201, resp.text

    logs = client.get("/api/v1/audit-logs").json()
    assert logs["total"] >= 1
    connect = [log for log in logs["items"] if log["action"] == "integration.connect"]
    assert connect, logs
    # The token must never appear anywhere in the audit record.
    assert "ghp_token" not in str(connect[0])
    assert connect[0]["resource_type"] == "integration"


def test_audit_filter_by_action(client: TestClient) -> None:
    client.post(
        "/api/v1/integrations",
        json={"provider": "github", "token": "ghp_token", "name": "acme"},
    )
    filtered = client.get("/api/v1/audit-logs?action=integration.connect").json()
    assert filtered["total"] >= 1
    assert all(i["action"] == "integration.connect" for i in filtered["items"])
