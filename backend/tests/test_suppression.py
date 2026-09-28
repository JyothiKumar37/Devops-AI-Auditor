"""Tests for finding suppression / baselines.

Covers suppressing a finding, the annotation + filter + count on the findings
list, un-suppressing, and the key baseline behaviour: a suppression carries over
to a future scan of the same repository automatically.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app

_DOCKERFILE = (
    b"FROM ubuntu:latest\n"
    b"RUN apt-get update\n"
    b"ENV DB_PASSWORD=hunter2plaintext\n"
    b"USER root\n"
)


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(  # type: ignore[arg-type]
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        workspace_root=str(tmp_path / "ws"),
    )
    app = create_app(settings=settings)
    with TestClient(app) as test_client:
        yield test_client


def _zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buffer.getvalue()


def _upload(client: TestClient, filename: str = "repo.zip") -> str:
    resp = client.post(
        "/api/v1/scans/upload",
        files={"file": (filename, _zip({"Dockerfile": _DOCKERFILE}), "application/zip")},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _findings(client: TestClient, scan_id: str, **params: object) -> dict:
    resp = client.get(f"/api/v1/scans/{scan_id}/findings", params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _find(client: TestClient, scan_id: str, rule_id: str, **params: object) -> dict:
    items = _findings(client, scan_id, **params)["items"]
    match = next((f for f in items if f["rule_id"] == rule_id), None)
    assert match is not None, f"{rule_id} not in {[f['rule_id'] for f in items]}"
    return match


def test_suppress_annotates_and_counts(client: TestClient) -> None:
    scan_id = _upload(client)
    finding = _find(client, scan_id, "DCK003")
    assert finding["suppressed"] is False

    resp = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding['id']}/suppress",
        json={"reason": "accepted_risk", "note": "reviewed by security"},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["reason"] == "accepted_risk"

    # The finding is now flagged suppressed, and the count reflects it.
    body = _findings(client, scan_id)
    assert body["suppressed_count"] == 1
    updated = next(f for f in body["items"] if f["rule_id"] == "DCK003")
    assert updated["suppressed"] is True
    assert updated["suppression_reason"] == "accepted_risk"
    assert updated["suppression_note"] == "reviewed by security"


def test_suppressed_filter(client: TestClient) -> None:
    scan_id = _upload(client)
    finding = _find(client, scan_id, "DCK003")
    client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding['id']}/suppress",
        json={"reason": "false_positive"},
    )

    only_suppressed = _findings(client, scan_id, suppressed=True)["items"]
    assert [f["rule_id"] for f in only_suppressed] == ["DCK003"]

    active = _findings(client, scan_id, suppressed=False)["items"]
    assert "DCK003" not in {f["rule_id"] for f in active}
    assert len(active) > 0


def test_unsuppress(client: TestClient) -> None:
    scan_id = _upload(client)
    finding = _find(client, scan_id, "DCK003")
    client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding['id']}/suppress",
        json={"reason": "wont_fix"},
    )
    assert _findings(client, scan_id)["suppressed_count"] == 1

    resp = client.delete(f"/api/v1/scans/{scan_id}/findings/{finding['id']}/suppress")
    assert resp.status_code == 204

    body = _findings(client, scan_id)
    assert body["suppressed_count"] == 0
    assert next(f for f in body["items"] if f["rule_id"] == "DCK003")["suppressed"] is False


def test_baseline_applies_to_future_scan_of_same_repo(client: TestClient) -> None:
    # Suppress in the first scan...
    first = _upload(client, "repo.zip")
    finding = _find(client, first, "DCK003")
    client.post(
        f"/api/v1/scans/{first}/findings/{finding['id']}/suppress",
        json={"reason": "accepted_risk"},
    )

    # ...a fresh scan of the same repository inherits the baseline automatically.
    second = _upload(client, "repo.zip")
    assert second != first
    inherited = _find(client, second, "DCK003")
    assert inherited["suppressed"] is True
    assert inherited["suppression_reason"] == "accepted_risk"


def test_list_suppressions(client: TestClient) -> None:
    scan_id = _upload(client)
    finding = _find(client, scan_id, "DCK003")
    client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding['id']}/suppress",
        json={"reason": "false_positive", "note": "test fixture"},
    )

    resp = client.get(f"/api/v1/scans/{scan_id}/suppressions")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["rule_id"] == "DCK003"
    assert body["items"][0]["reason"] == "false_positive"


def test_suppression_improves_readiness_report(client: TestClient) -> None:
    # Suppressing a finding must drop it from the report and not count against
    # the production-readiness score.
    scan_id = _upload(client)
    before = client.get(f"/api/v1/scans/{scan_id}/report").json()

    finding = _find(client, scan_id, "DCK005")  # critical plaintext secret
    resp = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding['id']}/suppress",
        json={"reason": "false_positive"},
    )
    assert resp.status_code == 201

    after = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert after["total_findings"] < before["total_findings"]
    assert after["production_readiness"]["score"] >= before["production_readiness"]["score"]


def test_suppress_unknown_finding_404(client: TestClient) -> None:
    scan_id = _upload(client)
    missing = "00000000-0000-0000-0000-000000000000"
    resp = client.post(
        f"/api/v1/scans/{scan_id}/findings/{missing}/suppress",
        json={"reason": "false_positive"},
    )
    assert resp.status_code == 404
