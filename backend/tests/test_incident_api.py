"""M12 tests: incident/security HTTP endpoints + webhook replay over the API.

Uses a module-scoped file-sqlite DB shared by path (the app owns its own engine),
mirroring the Phase 3 investigation-API test pattern. Covers the end-to-end HTTP
surface: ingest via webhook (signed), correlate, list/detail, lifecycle
transition (valid + invalid), containment generate/approve/execute, and webhook
replay rejection.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from core.config import Settings
from core.database import Database
from main import create_app
from services.security.webhook_auth import compute_signature

FERNET_KEY = Fernet.generate_key().decode()
WEBHOOK_SECRET = "test-secret"


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'incapi.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
        integration_encryption_key=FERNET_KEY,
    )


@pytest.fixture(scope="module")
def client(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    tmp_path = tmp_path_factory.mktemp("incapi")
    settings = _settings(tmp_path)

    async def _prepare() -> None:
        from services.security_service import SecurityService

        db = Database(settings)
        await db.create_all()
        async with db.sessionmaker() as session:
            svc = SecurityService(session, settings)
            await svc.register_source("cicd", secret=WEBHOOK_SECRET)
            await svc.register_source("falco", secret=WEBHOOK_SECRET)
            await session.commit()
        await db.dispose()

    asyncio.run(_prepare())
    with TestClient(create_app(settings=settings)) as c:
        yield c


def _signed(body: bytes, *, ts: str | None = None) -> dict[str, str]:
    ts = ts or str(int(time.time()))
    sig = compute_signature(WEBHOOK_SECRET, ts, body)
    return {"x-timestamp": ts, "x-signature": f"sha256={sig}"}


def _ingest_cicd(client: TestClient, *, failure_id: str, resource: str) -> None:
    payload = {
        "pipeline": "build", "repository": "acme/app", "commit": "c1",
        "failures": [{
            "id": failure_id, "rule": "trivy-crit", "severity": "critical",
            "title": "Critical CVE in image", "resource": resource,
        }],
    }
    body = json.dumps(payload).encode()
    resp = client.post("/api/v1/security/webhooks/cicd", content=body, headers=_signed(body))
    assert resp.status_code == 202, resp.text


def test_webhook_ingest_correlate_and_list(client: TestClient) -> None:
    _ingest_cicd(client, failure_id="f-list", resource="image:app:1")

    events = client.get("/api/v1/security/events").json()
    assert events["total"] >= 1

    # The webhook handler correlates immediately; an incident should exist.
    incidents = client.get("/api/v1/incidents").json()
    assert incidents["total"] >= 1


def test_incident_detail_and_lifecycle(client: TestClient) -> None:
    _ingest_cicd(client, failure_id="f-life", resource="image:life:1")
    incidents = client.get("/api/v1/incidents", params={"severity": "critical"}).json()
    incident_id = incidents["items"][0]["id"]

    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert detail["id"] == incident_id
    assert detail["priority"] > 0
    assert "factors" in detail["risk_rationale"]

    # Illegal transition new->contained is rejected (409).
    bad = client.post(
        f"/api/v1/incidents/{incident_id}/transition", json={"status": "contained"}
    )
    assert bad.status_code == 409

    # Valid transition new->investigating.
    good = client.post(
        f"/api/v1/incidents/{incident_id}/transition",
        json={"status": "investigating", "actor": "alice"},
    )
    assert good.status_code == 200
    assert good.json()["status"] == "investigating"


def test_containment_generate_approve_execute(client: TestClient) -> None:
    _ingest_cicd(client, failure_id="f-plan", resource="image:plan:1")
    incidents = client.get("/api/v1/incidents").json()
    incident_id = incidents["items"][0]["id"]

    gen = client.post(f"/api/v1/incidents/{incident_id}/remediation-plans")
    assert gen.status_code == 201, gen.text
    plans = gen.json()["items"] or client.get(
        f"/api/v1/incidents/{incident_id}/remediation-plans"
    ).json()["items"]
    assert plans
    plan_id = plans[0]["id"]

    # Execute before approval -> 409.
    early = client.post(f"/api/v1/remediation-plans/{plan_id}/execute", json={"actor": "x"})
    assert early.status_code == 409

    approve = client.post(
        f"/api/v1/remediation-plans/{plan_id}/approve", json={"approver": "alice"}
    )
    assert approve.status_code == 200
    assert approve.json()["status"] == "approved"

    execute = client.post(f"/api/v1/remediation-plans/{plan_id}/execute", json={"actor": "alice"})
    assert execute.status_code == 200
    # Vulnerability plan is PLAN-capability -> advisory 'skipped'.
    assert execute.json()["status"] in {"skipped", "not_enabled"}


def test_webhook_replay_rejected_over_http(client: TestClient) -> None:
    payload = {"rule": "x", "priority": "Warning"}
    body = json.dumps(payload).encode()
    stale = str(int(time.time()) - 10_000)
    resp = client.post(
        "/api/v1/security/webhooks/falco", content=body, headers=_signed(body, ts=stale)
    )
    assert resp.status_code == 401


def test_unknown_incident_404(client: TestClient) -> None:
    resp = client.get(f"/api/v1/incidents/{uuid.uuid4()}")
    assert resp.status_code == 404
