"""Tests for the policy management API (CRUD, versions, assign, evaluate)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app

POLICY_YAML = """\
version: 1
name: prod
rules:
  - id: no-critical
    condition:
      severity: critical
    action: fail
"""


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'pol.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )
    with TestClient(create_app(settings=settings)) as c:
        yield c


def test_create_rejects_invalid_yaml(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/policies",
        json={"name": "bad", "yaml_text": "name: x\nrules: []"},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_policy"


def test_crud_and_versioning(client: TestClient) -> None:
    created = client.post(
        "/api/v1/policies",
        json={"name": "prod", "yaml_text": POLICY_YAML, "description": "d"},
    )
    assert created.status_code == 201, created.text
    pid = created.json()["id"]
    assert created.json()["version"] == 1

    # Update YAML -> new version.
    extra_rule = (
        "  - id: warn-medium\n    condition: {severity: medium}\n    action: warn\n"
    )
    updated = client.put(
        f"/api/v1/policies/{pid}",
        json={"yaml_text": POLICY_YAML + extra_rule},
    )
    assert updated.status_code == 200
    assert updated.json()["version"] == 2

    versions = client.get(f"/api/v1/policies/{pid}/versions").json()
    assert len(versions) == 2

    assert client.get("/api/v1/policies").json()["total"] == 1
    assert client.delete(f"/api/v1/policies/{pid}").status_code == 204
    assert client.get("/api/v1/policies").json()["total"] == 0


def test_assign_and_evaluate_inline(client: TestClient) -> None:
    pid = client.post(
        "/api/v1/policies", json={"name": "prod", "yaml_text": POLICY_YAML}
    ).json()["id"]

    assigned = client.post(
        f"/api/v1/policies/{pid}/assign",
        json={"scope_type": "repo", "scope_value": "acme/web"},
    )
    assert assigned.status_code == 200

    # Evaluate against an inline finding list.
    result = client.post(
        f"/api/v1/policies/{pid}/evaluate",
        json={"findings": [{"rule_id": "X", "severity": "critical", "is_new": True}]},
    ).json()
    assert result["status"] == "fail"
    assert any(v["rule_id"] == "no-critical" for v in result["violations"])

    clean = client.post(
        f"/api/v1/policies/{pid}/evaluate",
        json={"findings": [{"rule_id": "X", "severity": "low"}]},
    ).json()
    assert clean["status"] == "pass"


def test_evaluate_requires_subject(client: TestClient) -> None:
    pid = client.post(
        "/api/v1/policies", json={"name": "prod", "yaml_text": POLICY_YAML}
    ).json()["id"]
    resp = client.post(f"/api/v1/policies/{pid}/evaluate", json={})
    assert resp.status_code == 422
