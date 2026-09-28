"""Tests for async (Celery-backed) scan execution.

These exercise the request/worker split without a running broker:
- the endpoint (in async mode) creates a PENDING scan and enqueues the task;
- running the pipeline directly (as the worker would, via its own database
  session) drives the scan to COMPLETED.

`run_*_scan.delay` is monkeypatched so no broker is contacted.
"""

from __future__ import annotations

import asyncio
import io
import uuid
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from core.database import Database
from main import create_app
from services.scan_service import ScanService
from workers.tasks import run_git_scan, run_zip_scan


def _zip() -> bytes:
    dockerfile = b"FROM ubuntu:latest\nENV DB_PASSWORD=hunter2plaintext\nUSER root\n"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Dockerfile", dockerfile)
    return buffer.getvalue()


@pytest.fixture
def async_ctx(tmp_path: Path) -> Iterator[tuple[TestClient, Settings]]:
    settings = Settings(  # type: ignore[arg-type]
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        workspace_root=str(tmp_path / "ws"),
        scan_async=True,
    )
    app = create_app(settings=settings)
    with TestClient(app) as client:
        yield client, settings


def _run_zip_pipeline(settings: Settings, scan_id: str) -> None:
    """Run the pipeline exactly as the Celery worker would: own DB session."""

    async def _go() -> None:
        database = Database(settings)
        try:
            async with database.sessionmaker() as session:
                await ScanService(session=session, settings=settings).run_zip_pipeline(
                    uuid.UUID(scan_id)
                )
        finally:
            await database.dispose()

    asyncio.run(_go())


def test_async_upload_returns_pending_then_pipeline_completes(
    async_ctx: tuple[TestClient, Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, settings = async_ctx
    monkeypatch.setattr(run_zip_scan, "delay", lambda *a, **k: None)

    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("repo.zip", _zip(), "application/zip")},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "pending"
    assert body["file_count"] == 0
    scan_id = body["id"]

    # The worker picks the scan up and runs it.
    _run_zip_pipeline(settings, scan_id)

    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan["status"] == "completed"
    assert scan["file_count"] > 0

    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    assert findings["total"] > 0


def test_async_upload_workspace_persists_until_pipeline_runs(
    async_ctx: tuple[TestClient, Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, settings = async_ctx
    monkeypatch.setattr(run_zip_scan, "delay", lambda *a, **k: None)
    scan_id = client.post(
        "/api/v1/scans/upload",
        files={"file": ("repo.zip", _zip(), "application/zip")},
    ).json()["id"]

    # The upload is persisted in the shared workspace for the worker to read...
    upload = Path(settings.workspace_root) / scan_id / "upload.bin"
    assert upload.exists()

    # ...and is cleaned up once the pipeline finishes.
    _run_zip_pipeline(settings, scan_id)
    assert not (Path(settings.workspace_root) / scan_id).exists()


def test_async_git_returns_pending_and_enqueues(
    async_ctx: tuple[TestClient, Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = async_ctx
    calls: list[tuple] = []
    monkeypatch.setattr(run_git_scan, "delay", lambda *a, **k: calls.append(a))

    response = client.post(
        "/api/v1/scans/git",
        json={"repository_url": "https://github.com/acme/repo.git"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "pending"
    assert body["source_type"] == "git"

    # The task was enqueued with (scan_id, url, ref).
    assert len(calls) == 1
    assert calls[0][0] == body["id"]
    assert calls[0][1] == "https://github.com/acme/repo.git"


def test_async_invalid_git_url_rejected_before_enqueue(
    async_ctx: tuple[TestClient, Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = async_ctx
    calls: list[tuple] = []
    monkeypatch.setattr(run_git_scan, "delay", lambda *a, **k: calls.append(a))

    response = client.post(
        "/api/v1/scans/git", json={"repository_url": "ftp://example.com/repo.git"}
    )
    assert response.status_code == 422
    assert calls == []  # nothing enqueued
    assert client.get("/api/v1/scans").json()["total"] == 0
