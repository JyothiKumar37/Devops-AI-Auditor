"""End-to-end tests for the scan ingestion API.

Runs the real FastAPI app against a temporary SQLite database and a temporary
workspace root, exercising the full upload -> extract -> index -> persist flow
plus the query endpoints and rejection paths.
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


def _make_settings(tmp_path: Path, **overrides: object) -> Settings:
    db_file = tmp_path / "test.db"
    workspace = tmp_path / "workspaces"
    base = {
        "environment": "development",
        "database_url_override": f"sqlite+aiosqlite:///{db_file}",
        "workspace_root": str(workspace),
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return _make_settings(tmp_path)


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings=settings)
    with TestClient(app) as test_client:
        yield test_client


def _repo_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Dockerfile", b"FROM python:3.11-slim\n")
        zf.writestr("docker-compose.yml", b"services: {}\n")
        zf.writestr("infra/main.tf", b'resource "null_resource" "x" {}\n')
        zf.writestr("scripts/deploy.sh", b"#!/bin/sh\necho hi\n")
        zf.writestr("README.md", b"# demo\n")
    return buffer.getvalue()


def _upload(client: TestClient, data: bytes, filename: str = "repo.zip") -> object:
    return client.post(
        "/api/v1/scans/upload",
        files={"file": (filename, data, "application/zip")},
    )


def test_full_upload_flow(client: TestClient, settings: Settings) -> None:
    response = _upload(client, _repo_zip())
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "completed"
    assert body["source_type"] == "zip"
    assert body["repository_name"] == "repo"
    assert body["file_count"] == 5
    scan_id = body["id"]

    # List
    listing = client.get("/api/v1/scans").json()
    assert listing["total"] == 1
    assert listing["items"][0]["id"] == scan_id
    assert listing["items"][0]["file_count"] == 5

    # Detail
    detail = client.get(f"/api/v1/scans/{scan_id}").json()
    assert detail["status"] == "completed"
    assert detail["started_at"] is not None
    assert detail["completed_at"] is not None

    # Files + classification
    files = client.get(f"/api/v1/scans/{scan_id}/files").json()
    assert files["total"] == 5
    by_path = {f["path"]: f for f in files["items"]}
    assert by_path["Dockerfile"]["file_type"] == "dockerfile"
    assert by_path["docker-compose.yml"]["file_type"] == "docker_compose"
    assert by_path["infra/main.tf"]["file_type"] == "terraform"
    assert by_path["scripts/deploy.sh"]["file_type"] == "shell"
    assert by_path["README.md"]["file_type"] == "other"
    assert all(len(f["checksum"]) == 64 for f in files["items"])

    # Workspace was cleaned up after completion.
    workspace_base = Path(settings.workspace_root)
    leftovers = (
        [p for p in workspace_base.glob("*") if p.is_dir()]
        if workspace_base.exists()
        else []
    )
    assert leftovers == []


def test_zip_slip_is_rejected_and_recorded(client: TestClient) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("../escape.txt", b"pwned")

    response = _upload(client, buffer.getvalue())
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_archive"

    # The failed scan is recorded and visible via the API.
    listing = client.get("/api/v1/scans").json()
    assert listing["total"] == 1
    assert listing["items"][0]["status"] == "failed"
    assert listing["items"][0]["error_message"]


def test_unsupported_extension_is_rejected(client: TestClient) -> None:
    response = _upload(client, b"not a zip", filename="notes.txt")
    assert response.status_code == 415
    # No scan record is created for a pre-flight rejection.
    assert client.get("/api/v1/scans").json()["total"] == 0


def test_oversized_upload_is_rejected(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path, max_upload_size_mb=0)
    app = create_app(settings=settings)
    with TestClient(app) as client:
        response = _upload(client, _repo_zip())
        assert response.status_code == 413
        listing = client.get("/api/v1/scans").json()
        assert listing["items"][0]["status"] == "failed"


def test_unknown_scan_returns_404(client: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/v1/scans/{missing}").status_code == 404
    assert client.get(f"/api/v1/scans/{missing}/files").status_code == 404
    assert client.get(f"/api/v1/scans/{missing}/discovery").status_code == 404


def _discovery_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Dockerfile", b"FROM alpine\n")
        zf.writestr(".github/workflows/ci.yml", b"name: ci\non: push\n")
        zf.writestr(
            "k8s/deployment.yaml",
            b"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
        )
        zf.writestr("infra/main.tf", b'resource "x" "y" {}\n')
        zf.writestr("config/app.toml", b"[a]\nb = 1\n")
    return buffer.getvalue()


def _vulnerable_docker_zip() -> bytes:
    dockerfile = (
        b"FROM ubuntu:latest\n"
        b"RUN apt-get update\n"
        b"RUN apt-get install -y curl\n"
        b"ENV DB_PASSWORD=hunter2plaintext\n"
        b"EXPOSE 22\n"
        b"USER root\n"
        b'CMD ["bash"]\n'
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Dockerfile", dockerfile)
        zf.writestr("README.md", b"# demo\n")
    return buffer.getvalue()


def test_findings_endpoint(client: TestClient) -> None:
    scan_id = _upload(client, _vulnerable_docker_zip()).json()["id"]  # type: ignore[attr-defined]

    response = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] > 0

    rule_ids = {item["rule_id"] for item in body["items"]}
    assert {"DCK001", "DCK003", "DCK005", "DCK006"} <= rule_ids

    # Findings carry the full schema.
    sample = body["items"][0]
    for field in (
        "id",
        "scan_id",
        "file_id",
        "category",
        "severity",
        "confidence",
        "title",
        "description",
        "recommendation",
        "rule_id",
        "scanner",
    ):
        assert field in sample

    # The finding is linked to the Dockerfile, not the README.
    secret = next(i for i in body["items"] if i["rule_id"] == "DCK005")
    assert secret["file_id"] is not None
    assert secret["scanner"] == "docker-rules"

    # Severity filtering works.
    high = client.get(f"/api/v1/scans/{scan_id}/findings?severity=high").json()
    assert high["total"] >= 1
    assert all(i["severity"] == "high" for i in high["items"])

    # Severity counts always cover the whole scan.
    assert sum(body["severity_counts"].values()) == body["total"]


def test_findings_unknown_scan_404(client: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/v1/scans/{missing}/findings").status_code == 404


def _shell_zip() -> bytes:
    script = (
        b"#!/bin/bash\n"
        b"curl -fsSL https://example.com/install.sh | bash\n"
        b"rm -rf $BUILD_DIR\n"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("scripts/deploy.sh", script)
    return buffer.getvalue()


def test_shell_scanner_findings_surface_via_api(client: TestClient) -> None:
    scan_id = _upload(client, _shell_zip()).json()["id"]  # type: ignore[attr-defined]

    body = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    by_rule = {item["rule_id"]: item for item in body["items"]}
    # The remote-pipe-to-shell and dangerous rm rules must be reported...
    assert "SH003" in by_rule
    assert "SH005" in by_rule
    # ...produced by the shell scanner and linked to the script file.
    assert by_rule["SH003"]["scanner"] == "shell-rules"
    assert by_rule["SH003"]["file_id"] is not None


def _ansible_zip() -> bytes:
    playbook = (
        b"---\n"
        b"- name: Deploy\n"
        b"  hosts: all\n"
        b"  tasks:\n"
        b"    - name: Fetch\n"
        b"      ansible.builtin.get_url:\n"
        b"        url: http://example.com/x\n"
        b"        validate_certs: no\n"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("site.yml", playbook)
    return buffer.getvalue()


def test_ansible_scanner_findings_surface_via_api(client: TestClient) -> None:
    scan_id = _upload(client, _ansible_zip()).json()["id"]  # type: ignore[attr-defined]

    body = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    by_rule = {item["rule_id"]: item for item in body["items"]}
    # TLS-disabled and insecure-URL rules must be reported by the ansible scanner.
    assert "ANS002" in by_rule
    assert by_rule["ANS002"]["scanner"] == "ansible-rules"
    assert by_rule["ANS002"]["file_id"] is not None


def _config_zip() -> bytes:
    config = b"debug: true\nssl_verify: false\nauthentication: none\n"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config/app.yaml", config)
    return buffer.getvalue()


def test_config_scanner_findings_surface_via_api(client: TestClient) -> None:
    scan_id = _upload(client, _config_zip()).json()["id"]  # type: ignore[attr-defined]

    body = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    by_rule = {item["rule_id"]: item for item in body["items"]}
    # Debug, TLS-verification-disabled and auth-disabled rules must be reported.
    assert {"CFG001", "CFG002", "CFG005"} <= set(by_rule)
    assert by_rule["CFG002"]["scanner"] == "config-rules"
    assert by_rule["CFG002"]["file_id"] is not None


def _helm_zip() -> bytes:
    chart = b"apiVersion: v1\nname: demo\ndescription: a chart\n"
    template = (
        b"apiVersion: apps/v1\n"
        b"kind: Deployment\n"
        b"spec:\n"
        b"  template:\n"
        b"    spec:\n"
        b"      containers:\n"
        b"        - name: app\n"
        b"          securityContext:\n"
        b"            privileged: true\n"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("demo/Chart.yaml", chart)
        zf.writestr("demo/templates/deployment.yaml", template)
    return buffer.getvalue()


def test_helm_scanner_findings_surface_via_api(client: TestClient) -> None:
    scan_id = _upload(client, _helm_zip()).json()["id"]  # type: ignore[attr-defined]

    body = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    by_rule = {item["rule_id"]: item for item in body["items"]}
    # Chart metadata rules plus the privileged-container rule from the template.
    assert "HELM001" in by_rule  # deprecated Helm 2 apiVersion (Chart.yaml)
    assert "HELM011" in by_rule  # privileged container (template)
    assert by_rule["HELM011"]["scanner"] == "helm-rules"
    assert by_rule["HELM011"]["file_id"] is not None


def test_discovery_endpoint_groups_files(client: TestClient) -> None:
    scan_id = _upload(client, _discovery_zip()).json()["id"]  # type: ignore[attr-defined]

    discovery = client.get(f"/api/v1/scans/{scan_id}/discovery").json()
    assert discovery["total"] == 5
    counts = discovery["counts"]
    assert counts["docker"] == 1
    assert counts["cicd"] == 1
    assert counts["kubernetes"] == 1
    assert counts["terraform"] == 1
    assert counts["configuration"] == 1

    categories = discovery["categories"]
    assert categories["kubernetes"][0]["path"] == "k8s/deployment.yaml"
    assert categories["kubernetes"][0]["file_type"] == "kubernetes"
    assert categories["docker"][0]["path"] == "Dockerfile"
