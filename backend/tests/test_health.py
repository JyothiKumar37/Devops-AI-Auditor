"""Tests for the meta and health endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_root_returns_service_info(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "DevOps AI Auditor"
    assert body["docs_url"] == "/docs"


def test_liveness_is_ok(client: TestClient) -> None:
    response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_reports_unhealthy_dependencies(client: TestClient) -> None:
    # Dependencies point at unreachable hosts, so readiness must report them as
    # unhealthy and return 503 - without the endpoint raising.
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "unhealthy"
    component_names = {c["name"] for c in body["components"]}
    assert component_names == {"postgres", "redis"}
