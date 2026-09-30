"""Tests for historical scan trends (per-repository aggregation)."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app

VULN = "FROM ubuntu:latest\nENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nUSER root\nEXPOSE 22\n"
CLEAN = "FROM ubuntu:24.04\nRUN echo ok\nUSER 1000\n"


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )
    with TestClient(create_app(settings=settings)) as test_client:
        yield test_client


def _zip(dockerfile: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Dockerfile", dockerfile)
    return buffer.getvalue()


def _upload(client: TestClient, dockerfile: str) -> str:
    # Same archive filename -> same repository_name -> same repository timeline.
    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("acme.zip", _zip(dockerfile), "application/zip")},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_trends_single_scan(client: TestClient) -> None:
    scan_id = _upload(client, VULN)
    body = client.get(f"/api/v1/scans/{scan_id}/trends").json()
    assert body["repository_name"] == "acme"
    assert body["total_scans"] == 1
    point = body["points"][0]
    # First scan: everything is "new", nothing fixed/unchanged.
    assert point["fixed_findings"] == 0
    assert point["unchanged_findings"] == 0
    assert point["new_findings"] >= 1
    assert 0 <= point["readiness"] <= 100


def test_trends_two_scans_show_improvement(client: TestClient) -> None:
    first = _upload(client, VULN)
    _upload(client, CLEAN)

    body = client.get(f"/api/v1/scans/{first}/trends").json()
    assert body["total_scans"] == 2
    p0, p1 = body["points"]
    # Points are chronological (oldest first).
    assert p0["created_at"] <= p1["created_at"]
    # The cleaner second scan fixes findings and improves readiness.
    assert p1["fixed_findings"] >= 1
    assert p1["readiness"] >= p0["readiness"]
    assert p1["total_findings"] <= p0["total_findings"]


def test_trends_points_have_severity_counts(client: TestClient) -> None:
    scan_id = _upload(client, VULN)
    body = client.get(f"/api/v1/scans/{scan_id}/trends").json()
    counts = body["points"][0]["severity_counts"]
    assert set(counts) >= {"critical", "high", "medium", "low", "info"}


def test_trends_scan_not_found(client: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/v1/scans/{missing}/trends").status_code == 404
