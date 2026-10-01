"""Tests for inbound webhook security, dedup, and dispatch (Milestone 4)."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import services.integration_service as integration_service
import services.webhook_service as webhook_service
from core.config import Settings
from main import create_app
from services.scm.fake import FakeSCMProvider, make_repo

SECRET = "whsec"
PAYLOAD = {
    "action": "synchronize",
    "number": 1,
    "repository": {"id": 42, "full_name": "acme/web"},
    "pull_request": {"number": 1, "head": {"sha": "h1", "ref": "feat"}, "base": {"ref": "main"}},
}


def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture
def dispatched(monkeypatch: pytest.MonkeyPatch) -> list:
    calls: list = []
    monkeypatch.setattr(
        webhook_service.WebhookService,
        "_default_dispatch",
        lambda self, provider, integration_id, repo, pr: calls.append(
            (provider, repo, pr)
        ),
    )
    # Connecting an integration uses the fake provider (no network).
    provider = FakeSCMProvider()
    provider.add_repo(make_repo("acme", "web"))
    monkeypatch.setattr(
        integration_service, "provider_factory", lambda n, t, s: provider
    )
    return calls


def _make_client(tmp_path: Path, max_body: int = 1_000_000) -> TestClient:
    settings = Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'wh.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
        integration_encryption_key=Fernet.generate_key().decode(),
        github_webhook_secret=SECRET,
        webhook_max_body_bytes=max_body,
    )
    return TestClient(create_app(settings=settings))


@pytest.fixture
def client(tmp_path: Path, dispatched: list) -> Iterator[TestClient]:
    with _make_client(tmp_path) as c:
        # A connected github integration so the webhook can resolve one.
        assert c.post(
            "/api/v1/integrations", json={"provider": "github", "token": "t"}
        ).status_code == 201
        yield c


def test_valid_webhook_accepted_and_dispatched(client: TestClient, dispatched: list) -> None:
    body = json.dumps(PAYLOAD).encode()
    resp = client.post(
        "/api/v1/webhooks/github",
        content=body,
        headers={
            "x-hub-signature-256": _sign(body),
            "x-github-event": "pull_request",
            "x-github-delivery": "d1",
            "content-type": "application/json",
        },
    )
    assert resp.status_code == 202, resp.text
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["scan_dispatched"] is True
    assert dispatched == [("github", "acme/web", 1)]


def test_duplicate_delivery_is_ignored(client: TestClient, dispatched: list) -> None:
    body = json.dumps(PAYLOAD).encode()
    headers = {
        "x-hub-signature-256": _sign(body),
        "x-github-event": "pull_request",
        "x-github-delivery": "dup",
    }
    first = client.post("/api/v1/webhooks/github", content=body, headers=headers)
    assert first.json()["status"] == "accepted"
    second = client.post("/api/v1/webhooks/github", content=body, headers=headers)
    assert second.json()["status"] == "duplicate"
    # Only the first delivery dispatched a scan.
    assert len(dispatched) == 1


def test_invalid_signature_rejected(client: TestClient, dispatched: list) -> None:
    body = json.dumps(PAYLOAD).encode()
    resp = client.post(
        "/api/v1/webhooks/github",
        content=body,
        headers={
            "x-hub-signature-256": "sha256=deadbeef",
            "x-github-event": "pull_request",
            "x-github-delivery": "bad",
        },
    )
    assert resp.status_code == 401
    assert dispatched == []


def test_oversized_payload_rejected(tmp_path: Path, dispatched: list) -> None:
    with _make_client(tmp_path, max_body=50) as c:
        c.post("/api/v1/integrations", json={"provider": "github", "token": "t"})
        body = json.dumps(PAYLOAD).encode()  # > 50 bytes
        resp = c.post(
            "/api/v1/webhooks/github",
            content=body,
            headers={"x-hub-signature-256": _sign(body), "x-github-event": "pull_request"},
        )
        assert resp.status_code == 413


def test_missing_signature_rejected(client: TestClient, dispatched: list) -> None:
    """A delivery with no signature header is unauthorized."""
    body = json.dumps(PAYLOAD).encode()
    resp = client.post(
        "/api/v1/webhooks/github",
        content=body,
        headers={"x-github-event": "pull_request", "x-github-delivery": "nosig"},
    )
    assert resp.status_code == 401
    assert dispatched == []


def test_no_integration_configured_rejected(tmp_path: Path, dispatched: list) -> None:
    """With no integration connected, a webhook cannot be authenticated."""
    with _make_client(tmp_path) as c:
        body = json.dumps(PAYLOAD).encode()
        resp = c.post(
            "/api/v1/webhooks/github",
            content=body,
            headers={
                "x-hub-signature-256": _sign(body),
                "x-github-event": "pull_request",
                "x-github-delivery": "noint",
            },
        )
        assert resp.status_code == 401
        assert dispatched == []


def test_webhook_route_is_exempt_from_api_key(tmp_path: Path, dispatched: list) -> None:
    """Even with an API key enforced, providers (no key) reach the webhook route."""
    settings = Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'wh2.db'}",
        workspace_root=str(tmp_path / "ws2"),
        llm_provider="none",
        integration_encryption_key=Fernet.generate_key().decode(),
        github_webhook_secret=SECRET,
        api_key="super-secret-key",
    )
    with TestClient(create_app(settings=settings)) as c:
        # No X-API-Key header, bad signature -> reaches handler and gets 401 from
        # signature check (NOT 401 from the API-key middleware). Integration is
        # missing too, but the point is the request is not blocked by the key.
        body = json.dumps(PAYLOAD).encode()
        resp = c.post(
            "/api/v1/webhooks/github",
            content=body,
            headers={"x-hub-signature-256": "sha256=bad", "x-github-event": "pull_request"},
        )
        # Reached the webhook handler (not the API-key gate): 401 webhook_unauthorized.
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] in {"webhook_unauthorized"}
