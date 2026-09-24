"""Tests for the scan-to-scan diff endpoint.

Exercises fingerprint-based matching of findings across two scans (new / fixed /
unchanged), the readiness delta, explicit vs auto-selected base, and the
no-previous-scan case. Runs the real app against a temporary SQLite database.
"""

from __future__ import annotations

import io
import time
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app


def _make_settings(tmp_path: Path) -> Settings:
    db_file = tmp_path / "test.db"
    return Settings(  # type: ignore[arg-type]
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{db_file}",
        workspace_root=str(tmp_path / "workspaces"),
    )


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    app = create_app(settings=_make_settings(tmp_path))
    with TestClient(app) as test_client:
        yield test_client


def _zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buffer.getvalue()


_VULNERABLE_DOCKERFILE = (
    b"FROM ubuntu:latest\n"
    b"RUN apt-get update\n"
    b"RUN apt-get install -y curl\n"
    b"ENV DB_PASSWORD=hunter2plaintext\n"
    b"EXPOSE 22\n"
    b"USER root\n"
    b'CMD ["bash"]\n'
)
_CLEAN_DOCKERFILE = b"FROM python:3.11-slim\nUSER app\n"


def _upload(client: TestClient, data: bytes, filename: str = "repo.zip") -> str:
    response = client.post(
        "/api/v1/scans/upload",
        files={"file": (filename, data, "application/zip")},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_diff_identical_scans_reports_all_unchanged(client: TestClient) -> None:
    payload = _zip({"Dockerfile": _VULNERABLE_DOCKERFILE, "README.md": b"# demo\n"})
    base_id = _upload(client, payload)
    head_id = _upload(client, payload)

    diff = client.get(f"/api/v1/scans/{head_id}/diff?base={base_id}").json()

    assert diff["base_scan_id"] == base_id
    assert diff["head_scan_id"] == head_id
    assert diff["summary"]["new"] == 0
    assert diff["summary"]["fixed"] == 0
    assert diff["summary"]["unchanged"] > 0
    assert diff["summary"]["unchanged"] == diff["summary"]["head_total"]
    # Identical content → identical findings → identical readiness.
    assert diff["readiness_delta"] == 0
    assert diff["base_readiness"] == diff["head_readiness"]
    assert diff["new_findings"] == []
    assert diff["fixed_findings"] == []


def test_diff_reports_fixed_findings_and_readiness_gain(client: TestClient) -> None:
    base_id = _upload(client, _zip({"Dockerfile": _VULNERABLE_DOCKERFILE}))
    head_id = _upload(client, _zip({"Dockerfile": _CLEAN_DOCKERFILE}))

    diff = client.get(f"/api/v1/scans/{head_id}/diff?base={base_id}").json()

    assert diff["summary"]["fixed"] > 0
    # The vulnerable Dockerfile's issues are gone in the clean one.
    fixed_rules = {f["rule_id"] for f in diff["fixed_findings"]}
    assert "DCK005" in fixed_rules  # plaintext secret in ENV
    # Fewer/less-severe issues → readiness improves (delta >= 0, base <= head).
    assert diff["readiness_delta"] is not None
    assert diff["head_readiness"] >= diff["base_readiness"]
    # Per-severity counts are consistent with the fixed list length.
    assert sum(diff["fixed_severity_counts"].values()) == diff["summary"]["fixed"]


def test_diff_reports_new_findings(client: TestClient) -> None:
    base_id = _upload(client, _zip({"Dockerfile": _CLEAN_DOCKERFILE}))
    head_id = _upload(client, _zip({"Dockerfile": _VULNERABLE_DOCKERFILE}))

    diff = client.get(f"/api/v1/scans/{head_id}/diff?base={base_id}").json()

    assert diff["summary"]["new"] > 0
    new_rules = {f["rule_id"] for f in diff["new_findings"]}
    assert "DCK005" in new_rules
    assert sum(diff["new_severity_counts"].values()) == diff["summary"]["new"]


def test_diff_auto_selects_previous_scan(client: TestClient) -> None:
    base_id = _upload(client, _zip({"Dockerfile": _VULNERABLE_DOCKERFILE}))
    # created_at has second resolution on SQLite; ensure a distinct timestamp.
    time.sleep(1.1)
    head_id = _upload(client, _zip({"Dockerfile": _CLEAN_DOCKERFILE}))

    diff = client.get(f"/api/v1/scans/{head_id}/diff").json()
    assert diff["base_scan_id"] == base_id
    assert diff["summary"]["fixed"] > 0


def test_diff_with_no_previous_scan_marks_everything_new(client: TestClient) -> None:
    head_id = _upload(client, _zip({"Dockerfile": _VULNERABLE_DOCKERFILE}))

    diff = client.get(f"/api/v1/scans/{head_id}/diff").json()

    assert diff["base_scan_id"] is None
    assert diff["base_readiness"] is None
    assert diff["readiness_delta"] is None
    assert diff["summary"]["fixed"] == 0
    assert diff["summary"]["unchanged"] == 0
    assert diff["summary"]["new"] == diff["summary"]["head_total"] > 0


def test_diff_unknown_scans_return_404(client: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/v1/scans/{missing}/diff").status_code == 404

    real = _upload(client, _zip({"Dockerfile": _CLEAN_DOCKERFILE}))
    assert client.get(f"/api/v1/scans/{real}/diff?base={missing}").status_code == 404
