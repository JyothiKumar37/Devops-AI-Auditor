"""Tests for the remediation history audit trail and before/after snapshots."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app

DOCKER_USER_ROOT = "FROM python:3.11-slim\nRUN echo hi\nUSER root\n"


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


def _zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buffer.getvalue()


def _upload(client: TestClient, files: dict[str, bytes]) -> str:
    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("repo.zip", _zip(files), "application/zip")},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _finding_by_rule(client: TestClient, scan_id: str, rule_id: str) -> dict:
    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()["items"]
    matches = [f for f in findings if f["rule_id"] == rule_id]
    assert matches, f"expected {rule_id}"
    return matches[0]


def test_history_empty_before_any_remediation(client: TestClient) -> None:
    scan_id = _upload(client, {"Dockerfile": DOCKER_USER_ROOT.encode()})
    body = client.get(f"/api/v1/scans/{scan_id}/remediation-history").json()
    assert body["total"] == 0
    assert body["resolved_count"] == 0
    assert body["items"] == []


def test_apply_records_history_with_before_after(client: TestClient) -> None:
    scan_id = _upload(client, {"Dockerfile": DOCKER_USER_ROOT.encode()})
    finding = _finding_by_rule(client, scan_id, "DCK003")
    fid = finding["id"]
    severity = finding["severity"]

    result = client.post(
        f"/api/v1/scans/{scan_id}/findings/{fid}/remediation/apply"
    ).json()
    assert result["applied"] is True
    assert result["resolved"] is True
    assert result["severity"] == severity
    # A verified resolution removes exactly one finding of that severity.
    assert result["before_counts"][severity] - result["after_counts"][severity] == 1

    history = client.get(f"/api/v1/scans/{scan_id}/remediation-history").json()
    assert history["total"] == 1
    assert history["resolved_count"] == 1
    record = history["items"][0]
    assert record["rule_id"] == "DCK003"
    assert record["applied"] is True
    assert record["resolved"] is True
    assert record["diff"]
    assert record["before_counts"][severity] - record["after_counts"][severity] == 1
    assert record["file_path"] == "Dockerfile"


def test_manual_apply_records_no_history(client: TestClient) -> None:
    # An unfixable finding (latest tag) yields a manual result and must NOT be
    # written to the applied-remediation audit trail.
    scan_id = _upload(client, {"Dockerfile": b"FROM ubuntu:latest\nUSER 1000\n"})
    finding = _finding_by_rule(client, scan_id, "DCK001")
    fid = finding["id"]

    result = client.post(
        f"/api/v1/scans/{scan_id}/findings/{fid}/remediation/apply"
    ).json()
    assert result["applied"] is False

    history = client.get(f"/api/v1/scans/{scan_id}/remediation-history").json()
    assert history["total"] == 0
