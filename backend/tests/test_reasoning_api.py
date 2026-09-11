"""Integration test: the /report endpoint over a real scan (SQLite, no LLM)."""

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
        llm_provider="none",
    )
    with TestClient(create_app(settings=settings)) as test_client:
        yield test_client


def _vulnerable_zip() -> bytes:
    dockerfile = (
        b"FROM ubuntu:latest\n"
        b"ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        b"USER root\n"
        b'CMD ["bash"]\n'
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Dockerfile", dockerfile)
        zf.writestr("README.md", b"# demo\n")
    return buffer.getvalue()


def test_report_endpoint(client: TestClient) -> None:
    upload = client.post(
        "/api/v1/scans/upload",
        files={"file": ("repo.zip", _vulnerable_zip(), "application/zip")},
    )
    assert upload.status_code == 201
    scan_id = upload.json()["id"]

    response = client.get(f"/api/v1/scans/{scan_id}/report")
    assert response.status_code == 200, response.text
    report = response.json()

    assert report["scan_id"] == scan_id
    assert report["llm_used"] is False
    assert report["total_findings"] > 0
    assert "Docker" in report["understanding"]["technologies"]
    assert report["production_readiness"]["ready"] is False  # critical secret present

    assert report["key_findings"], "expected reasoned key findings"
    for kf in report["key_findings"]:
        # Each AI finding must carry the mandatory evidence trail.
        assert kf["evidence"]
        assert kf["source"]
        assert kf["reasoning"]
        assert kf["recommendation"]

    # A masked AWS key should surface; its raw value must never appear.
    blob = response.text
    assert "AKIAIOSFODNN7EXAMPLE" not in blob


def test_report_unknown_scan_returns_404(client: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/v1/scans/{missing}/report").status_code == 404
