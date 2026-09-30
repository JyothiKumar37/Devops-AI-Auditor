"""Tests for the deterministic posture engine and the /posture endpoint."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app
from services.posture import POSTURE_DOMAINS, assess_posture, domains_for

# ---------------------------------------------------------------------------
# Pure engine tests
# ---------------------------------------------------------------------------


def _f(**kw: object) -> dict[str, object]:
    base = {
        "scanner": "docker-rules",
        "rule_id": "DCK001",
        "category": "best_practice",
        "severity": "high",
        "confidence": "high",
    }
    base.update(kw)
    return base


def test_domains_overlap_for_k8s_security() -> None:
    # A Kubernetes security finding belongs to both lenses.
    d = domains_for(_f(scanner="kubernetes-rules", category="security"))
    assert "kubernetes" in d
    assert "security" in d


def test_secret_maps_to_secrets_and_security() -> None:
    d = domains_for(_f(scanner="secret-scanner", category="secrets"))
    assert {"secrets", "security"} <= d


def test_all_domains_present_in_output() -> None:
    scores = assess_posture([], [])
    keys = {s.key for s in scores}
    assert keys == {key for key, _ in POSTURE_DOMAINS}


def test_clean_repo_scores_full() -> None:
    files = [{"file_type": "dockerfile"}]
    scores = {s.key: s for s in assess_posture([], files)}
    assert scores["containers"].score == 100
    assert scores["security"].score == 100


def test_findings_reduce_domain_score() -> None:
    files = [{"file_type": "dockerfile"}]
    findings = [_f(scanner="docker-rules", severity="critical", category="security")]
    scores = {s.key: s for s in assess_posture(findings, files)}
    # A critical hits both containers (by scanner) and security (by category).
    assert scores["containers"].score < 100
    assert scores["security"].score < 100


def test_dependencies_not_applicable_without_findings() -> None:
    scores = {s.key: s for s in assess_posture([], [{"file_type": "dockerfile"}])}
    assert scores["dependencies"].applicable is False


def test_terraform_applicable_from_filetype() -> None:
    scores = {s.key: s for s in assess_posture([], [{"file_type": "terraform"}])}
    assert scores["terraform"].applicable is True


def test_non_applicable_domain_stays_full_score() -> None:
    # No kubernetes files and no k8s findings -> not applicable, score pinned 100.
    scores = {s.key: s for s in assess_posture([], [{"file_type": "dockerfile"}])}
    assert scores["kubernetes"].applicable is False
    assert scores["kubernetes"].score == 100


# ---------------------------------------------------------------------------
# API test (SQLite-backed scan)
# ---------------------------------------------------------------------------

VULN_DOCKERFILE = """\
FROM ubuntu:latest
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
USER root
CMD ["bash"]
"""

VULN_K8S = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 1
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
        - name: api
          image: myregistry/api:latest
          securityContext:
            privileged: true
"""

FILES = {
    "Dockerfile": VULN_DOCKERFILE,
    "k8s/deploy.yaml": VULN_K8S,
    "README.md": "# demo\n",
}


def _zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buffer.getvalue()


@pytest.fixture(scope="module")
def client(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    root = tmp_path_factory.mktemp("posture")
    settings = Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{root / 'posture.db'}",
        workspace_root=str(root / "ws"),
        llm_provider="none",
    )
    with TestClient(create_app(settings=settings)) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def scan_id(client: TestClient) -> str:
    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("repo.zip", _zip(FILES), "application/zip")},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_posture_endpoint_shape(client: TestClient, scan_id: str) -> None:
    body = client.get(f"/api/v1/scans/{scan_id}/posture").json()
    assert 0 <= body["overall"] <= 100
    keys = {c["key"] for c in body["categories"]}
    assert keys == {key for key, _ in POSTURE_DOMAINS}
    for c in body["categories"]:
        assert 0 <= c["score"] <= 100
        assert c["explanation"]


def test_posture_reflects_findings(client: TestClient, scan_id: str) -> None:
    body = client.get(f"/api/v1/scans/{scan_id}/posture").json()
    cats = {c["key"]: c for c in body["categories"]}
    # Containers and kubernetes are applicable (Dockerfile + k8s manifest present).
    assert cats["containers"]["applicable"] is True
    assert cats["kubernetes"]["applicable"] is True
    # The repo has real issues, so the overall posture is not perfect.
    assert body["overall"] < 100
    assert body["total_findings"] >= 1


def test_posture_has_affected_files_and_recommendations(
    client: TestClient, scan_id: str
) -> None:
    body = client.get(f"/api/v1/scans/{scan_id}/posture").json()
    assert body["most_affected_files"]
    assert all("file" in a and "findings" in a for a in body["most_affected_files"])
    # Top risk areas are applicable domains scoring below 100.
    for area in body["top_risk_areas"]:
        assert area["applicable"] is True
        assert area["score"] < 100
