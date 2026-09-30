"""Tests for the container-security score engine, the new --chmod check, endpoint."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app
from scanners.docker import DockerScanner
from services.container_score import (
    CONTAINER_CATEGORIES,
    assess_container,
    category_for_rule,
)

# ---------------------------------------------------------------------------
# New Docker rule: world-writable --chmod
# ---------------------------------------------------------------------------


def _docker(text: str) -> list:
    return DockerScanner().analyze_text(text, "Dockerfile")


def test_world_writable_chmod_flagged() -> None:
    text = "FROM python:3.11-slim\nCOPY --chmod=777 app.py /app/app.py\nUSER 1000\n"
    findings = _docker(text)
    assert any(f.rule_id == "DCK014" and "world-writable" in f.description for f in findings)


def test_symbolic_world_writable_chmod_flagged() -> None:
    text = "FROM python:3.11-slim\nADD --chmod=o+w a.txt /a.txt\nUSER 1000\n"
    findings = _docker(text)
    assert any(f.rule_id == "DCK014" for f in findings)


def test_safe_chmod_not_flagged() -> None:
    text = "FROM python:3.11-slim\nCOPY --chmod=755 app.py /app/app.py\nUSER 1000\n"
    findings = _docker(text)
    assert not any(
        f.rule_id == "DCK014" and "world-writable" in f.description for f in findings
    )


# ---------------------------------------------------------------------------
# Pure score engine
# ---------------------------------------------------------------------------


def test_rule_category_mapping() -> None:
    assert category_for_rule("DCK001") == "image_hygiene"
    assert category_for_rule("DCK004") == "runtime_hardening"
    assert category_for_rule("DCK008") == "build_quality"
    assert category_for_rule("DCK005") == "security"  # secrets -> security
    assert category_for_rule("DCMP017") == "security"  # docker socket
    assert category_for_rule("DCMP015") == "image_hygiene"
    assert category_for_rule("DCMP010") == "runtime_hardening"
    assert category_for_rule("DCK999") == "security"  # default


def test_not_applicable_without_containers() -> None:
    score = assess_container([], has_containers=False)
    assert score.applicable is False
    assert score.overall == 100


def test_all_dimensions_present_and_perfect_when_clean() -> None:
    score = assess_container([], has_containers=True)
    keys = {c.key for c in score.categories}
    assert keys == {key for key, _, _ in CONTAINER_CATEGORIES}
    assert score.overall == 100


def test_findings_reduce_relevant_dimension() -> None:
    findings = [
        {"rule_id": "DCK003", "severity": "high", "confidence": "high"},   # runtime
        {"rule_id": "DCK001", "severity": "medium", "confidence": "high"},  # image hygiene
    ]
    score = assess_container(findings, has_containers=True)
    cats = {c.key: c for c in score.categories}
    assert cats["runtime_hardening"].score < 100
    assert cats["image_hygiene"].score < 100
    assert cats["build_quality"].score == 100
    assert score.overall < 100


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

VULN_DOCKERFILE = """\
FROM ubuntu:latest
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
RUN apt-get install -y curl
USER root
"""


def _zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buffer.getvalue()


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


def _upload(client: TestClient, files: dict[str, str]) -> str:
    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("repo.zip", _zip(files), "application/zip")},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_container_security_endpoint_applicable(client: TestClient) -> None:
    scan_id = _upload(client, {"Dockerfile": VULN_DOCKERFILE})
    body = client.get(f"/api/v1/scans/{scan_id}/container-security").json()
    assert body["applicable"] is True
    assert 0 <= body["overall"] <= 100
    keys = {c["key"] for c in body["categories"]}
    assert keys == {key for key, _, _ in CONTAINER_CATEGORIES}
    assert body["overall"] < 100  # the vulnerable Dockerfile has real issues


def test_container_security_not_applicable(client: TestClient) -> None:
    scan_id = _upload(client, {"README.md": "# docs only\n"})
    body = client.get(f"/api/v1/scans/{scan_id}/container-security").json()
    assert body["applicable"] is False
    assert body["overall"] == 100
