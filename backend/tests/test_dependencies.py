"""Tests for dependency inventory parsing, CycloneDX SBOM, and endpoints."""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app
from services.dependencies import (
    build_cyclonedx,
    manifest_kind,
    parse_manifests,
    purl_for,
)

# ---------------------------------------------------------------------------
# Manifest detection + parsing (pure)
# ---------------------------------------------------------------------------

PACKAGE_JSON = json.dumps(
    {
        "name": "web",
        "dependencies": {"express": "^4.18.2", "left-pad": "1.3.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }
)

PACKAGE_LOCK = json.dumps(
    {
        "name": "web",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "web", "version": "1.0.0"},
            "node_modules/express": {"version": "4.18.2", "license": "MIT"},
            "node_modules/express/node_modules/cookie": {"version": "0.5.0"},
        },
    }
)

REQUIREMENTS = "flask==2.3.0\nrequests>=2.28\n# a comment\n-r other.txt\ndjango\n"

PYPROJECT = """\
[project]
name = "svc"
dependencies = ["fastapi>=0.110", "pydantic==2.6.0"]

[tool.poetry.dependencies]
python = "^3.11"
httpx = "^0.27"
"""

POETRY_LOCK = """\
[[package]]
name = "anyio"
version = "4.3.0"

[[package]]
name = "sniffio"
version = "1.3.1"
"""


def test_manifest_kind_detection() -> None:
    assert manifest_kind("package.json") == "npm_manifest"
    assert manifest_kind("frontend/package-lock.json") == "npm_lock"
    assert manifest_kind("requirements.txt") == "pip_requirements"
    assert manifest_kind("requirements-dev.txt") == "pip_requirements"
    assert manifest_kind("pyproject.toml") == "pyproject"
    assert manifest_kind("poetry.lock") == "poetry_lock"
    assert manifest_kind("mypackage.json") is None
    assert manifest_kind("src/main.py") is None


def test_parse_package_json_direct() -> None:
    comps = parse_manifests([("package.json", PACKAGE_JSON)])
    by_name = {c.name: c for c in comps}
    assert "express" in by_name
    assert by_name["express"].ecosystem == "npm"
    assert by_name["express"].direct is True
    assert by_name["express"].version == "4.18.2"  # range operator stripped
    assert by_name["left-pad"].version == "1.3.0"


def test_parse_lock_marks_transitive_and_merges() -> None:
    comps = parse_manifests([("package.json", PACKAGE_JSON), ("package-lock.json", PACKAGE_LOCK)])
    by_name = {c.name: c for c in comps}
    # express is in both -> direct, exact version from lock, license from lock.
    assert by_name["express"].direct is True
    assert by_name["express"].version == "4.18.2"
    assert by_name["express"].license == "MIT"
    # cookie only exists in the lock, nested -> transitive.
    assert "cookie" in by_name
    assert by_name["cookie"].direct is False


def test_parse_requirements() -> None:
    comps = parse_manifests([("requirements.txt", REQUIREMENTS)])
    by_name = {c.name: c for c in comps}
    assert by_name["flask"].version == "2.3.0"
    assert by_name["flask"].ecosystem == "pypi"
    assert "requests" in by_name
    assert "django" in by_name  # unpinned -> version "unknown"
    assert by_name["django"].version == "unknown"


def test_parse_pyproject_pep621_and_poetry() -> None:
    comps = parse_manifests([("pyproject.toml", PYPROJECT)])
    names = {c.name for c in comps}
    assert {"fastapi", "pydantic", "httpx"} <= names
    assert "python" not in names  # the python constraint is skipped


def test_parse_poetry_lock() -> None:
    comps = parse_manifests([("poetry.lock", POETRY_LOCK)])
    by_name = {c.name: c for c in comps}
    assert by_name["anyio"].version == "4.3.0"
    assert by_name["anyio"].direct is False  # lock entries are transitive by default


def test_purl_format() -> None:
    pkg = json.dumps({"dependencies": {"@scope/pkg": "1.0.0"}})
    comps = parse_manifests([("package.json", pkg)])
    purl = purl_for(comps[0])
    assert purl == "pkg:npm/%40scope/pkg@1.0.0"


def test_build_cyclonedx_shape() -> None:
    comps = parse_manifests([("requirements.txt", "flask==2.3.0\n")])
    sbom = build_cyclonedx("myrepo", comps)
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["serialNumber"].startswith("urn:uuid:")
    assert sbom["metadata"]["component"]["name"] == "myrepo"
    comp = sbom["components"][0]
    assert comp["type"] == "library"
    assert comp["name"] == "flask"
    assert comp["purl"] == "pkg:pypi/flask@2.3.0"
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["aad:ecosystem"] == "pypi"
    assert props["aad:scope"] == "direct"


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


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


def test_dependencies_endpoint(client: TestClient) -> None:
    scan_id = _upload(client, {"package.json": PACKAGE_JSON, "requirements.txt": REQUIREMENTS})
    body = client.get(f"/api/v1/scans/{scan_id}/dependencies").json()
    assert body["total"] >= 5
    assert body["direct"] >= 5
    assert body["ecosystem_counts"]["npm"] >= 2
    assert body["ecosystem_counts"]["pypi"] >= 3
    # Honest about the absence of a vulnerability database.
    assert body["vulnerabilities_available"] is False
    assert body["vulnerability_counts"]["critical"] == 0
    names = {i["name"] for i in body["items"]}
    assert "express" in names and "flask" in names


def test_sbom_endpoint_is_cyclonedx(client: TestClient) -> None:
    scan_id = _upload(client, {"requirements.txt": "flask==2.3.0\n"})
    resp = client.get(f"/api/v1/scans/{scan_id}/sbom")
    assert resp.status_code == 200
    assert "cyclonedx" in resp.headers["content-type"]
    sbom = resp.json()
    assert sbom["bomFormat"] == "CycloneDX"
    assert any(c["name"] == "flask" for c in sbom["components"])


def test_sbom_download_disposition(client: TestClient) -> None:
    scan_id = _upload(client, {"requirements.txt": "flask==2.3.0\n"})
    resp = client.get(f"/api/v1/scans/{scan_id}/sbom?download=true")
    assert "attachment" in resp.headers["content-disposition"]
    assert ".cdx.json" in resp.headers["content-disposition"]


def test_dependencies_empty_repo(client: TestClient) -> None:
    scan_id = _upload(client, {"README.md": "# no deps\n"})
    body = client.get(f"/api/v1/scans/{scan_id}/dependencies").json()
    assert body["total"] == 0
    assert body["items"] == []
