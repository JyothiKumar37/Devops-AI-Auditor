"""Tests for ingesting a repository directly from a git URL.

These exercise the full clone -> discover -> scan -> persist flow end to end.
To avoid any network dependency the tests create a throwaway local git
repository and clone it via a ``file://`` URL, enabling the local-clone escape
hatch that is off by default in production.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app


def _make_settings(tmp_path: Path, **overrides: object) -> Settings:
    db_file = tmp_path / "test.db"
    workspace = tmp_path / "workspaces"
    base: dict[str, object] = {
        "environment": "development",
        "database_url_override": f"sqlite+aiosqlite:///{db_file}",
        "workspace_root": str(workspace),
        "git_allow_local_clones": True,
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def _client(settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings=settings)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return _make_settings(tmp_path)


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    yield from _client(settings)


def _git(cwd: Path, *args: str) -> None:
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    subprocess.run(
        ["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True
    )


def _make_source_repo(path: Path) -> str:
    """Create a small local git repo and return a ``file://`` clone URL."""
    path.mkdir(parents=True, exist_ok=True)
    (path / "Dockerfile").write_text(
        "FROM ubuntu:latest\nRUN apt-get update\nUSER root\nCMD [\"bash\"]\n"
    )
    (path / "docker-compose.yml").write_text("services: {}\n")
    (path / "README.md").write_text("# demo repo\n")
    _git(path, "init", "-q")
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "initial commit")
    return f"file://{path}"


def test_git_ingestion_flow(client: TestClient, settings: Settings, tmp_path: Path) -> None:
    url = _make_source_repo(tmp_path / "source")

    response = client.post("/api/v1/scans/git", json={"repository_url": url})
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "completed"
    assert body["source_type"] == "git"
    assert body["repository_name"] == "source"
    # Dockerfile, docker-compose.yml, README.md — and never any .git internals.
    assert body["file_count"] == 3
    scan_id = body["id"]

    files = client.get(f"/api/v1/scans/{scan_id}/files").json()
    paths = {f["path"] for f in files["items"]}
    assert paths == {"Dockerfile", "docker-compose.yml", "README.md"}
    assert not any(p.startswith(".git") for p in paths)

    # The Dockerfile scanner still runs on the cloned tree.
    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    assert findings["total"] > 0

    # Workspace (including the clone) is cleaned up on completion.
    workspace_base = Path(settings.workspace_root)
    leftovers = (
        [p for p in workspace_base.glob("*") if p.is_dir()]
        if workspace_base.exists()
        else []
    )
    assert leftovers == []


def test_git_unsupported_scheme_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/scans/git", json={"repository_url": "ftp://example.com/repo.git"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_repository"
    # Rejected before any scan row is created.
    assert client.get("/api/v1/scans").json()["total"] == 0


def test_git_clone_failure_is_recorded(client: TestClient, tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    response = client.post(
        "/api/v1/scans/git", json={"repository_url": f"file://{missing}"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_repository"

    # The failed scan is recorded and visible via the API.
    listing = client.get("/api/v1/scans").json()
    assert listing["total"] == 1
    assert listing["items"][0]["status"] == "failed"
    assert listing["items"][0]["source_type"] == "git"
    assert listing["items"][0]["error_message"]


def test_git_ingestion_can_be_disabled(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path, git_ingestion_enabled=False)
    app = create_app(settings=settings)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans/git", json={"repository_url": "https://example.com/x.git"}
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "git_ingestion_disabled"
        assert client.get("/api/v1/scans").json()["total"] == 0


def test_git_host_allowlist_enforced(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path, git_allowed_hosts="github.com")
    app = create_app(settings=settings)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans/git",
            json={"repository_url": "https://gitlab.com/acme/repo.git"},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "invalid_repository"
