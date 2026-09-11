"""Tests for the dashboard stats and file-content endpoints."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        workspace_root=str(tmp_path / "ws"),
    )
    with TestClient(create_app(settings=settings)) as test_client:
        yield test_client


def _zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Dockerfile", b"FROM ubuntu:latest\nUSER root\nENV KEY=AKIAIOSFODNN7EXAMPLE\n")
        zf.writestr("README.md", b"# demo project\n")
    return buffer.getvalue()


def _upload(client: TestClient) -> str:
    resp = client.post(
        "/api/v1/scans/upload",
        files={"file": ("repo.zip", _zip(), "application/zip")},
    )
    assert resp.status_code == 201
    return resp.json()["id"]


def test_stats_endpoint(client: TestClient) -> None:
    _upload(client)
    stats = client.get("/api/v1/stats").json()
    assert stats["total_scans"] == 1
    assert stats["repositories_scanned"] >= 1
    assert stats["critical_issues"] >= 1  # the AWS key
    assert 0 <= stats["average_readiness"] <= 100
    assert stats["latest_scans"] and stats["latest_scans"][0]["file_count"] == 2


def test_file_content_endpoint(client: TestClient) -> None:
    scan_id = _upload(client)
    files = client.get(f"/api/v1/scans/{scan_id}/files").json()["items"]
    dockerfile = next(f for f in files if f["path"] == "Dockerfile")

    resp = client.get(f"/api/v1/scans/{scan_id}/files/{dockerfile['id']}/content")
    assert resp.status_code == 200
    body = resp.json()
    assert body["path"] == "Dockerfile"
    assert "FROM ubuntu:latest" in body["content"]


def test_findings_confidence_and_filetype_filters(client: TestClient) -> None:
    scan_id = _upload(client)
    high = client.get(f"/api/v1/scans/{scan_id}/findings?confidence=high").json()
    assert all(i["confidence"] == "high" for i in high["items"])
    docker = client.get(f"/api/v1/scans/{scan_id}/findings?file_type=dockerfile").json()
    assert docker["total"] >= 1


def test_file_content_unknown_returns_404(client: TestClient) -> None:
    scan_id = _upload(client)
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/v1/scans/{scan_id}/files/{missing}/content").status_code == 404
