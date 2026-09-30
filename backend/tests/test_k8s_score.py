"""Tests for the Kubernetes readiness score engine, new K8S rules, and endpoint."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app
from scanners.kubernetes import KubernetesScanner
from services.k8s_score import K8S_CATEGORIES, assess_k8s, category_for_rule

# ---------------------------------------------------------------------------
# New scanner rules
# ---------------------------------------------------------------------------


def _scan(text: str) -> set[str]:
    findings = KubernetesScanner().analyze_manifests([("k8s.yaml", text)])
    return {f.rule_id for f in findings}


AUTOMOUNT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      automountServiceAccountToken: true
      containers:
        - name: api
          image: myrepo/api:1.2.3
"""

EXPOSED_NO_NETPOL = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: shop
spec:
  replicas: 2
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
          image: myrepo/api:1.2.3
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: shop
spec:
  type: LoadBalancer
  selector:
    app: api
  ports:
    - port: 80
      targetPort: 8080
"""

WITH_NETPOL = EXPOSED_NO_NETPOL + """\
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: shop
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
"""


def test_automount_token_flagged_when_explicit_true() -> None:
    assert "K8S012" in _scan(AUTOMOUNT)


def test_networkpolicy_missing_flagged_for_exposed_namespace() -> None:
    assert "K8S042" in _scan(EXPOSED_NO_NETPOL)


def test_networkpolicy_present_not_flagged() -> None:
    assert "K8S042" not in _scan(WITH_NETPOL)


# ---------------------------------------------------------------------------
# Pure score engine
# ---------------------------------------------------------------------------


def test_rule_category_mapping() -> None:
    assert category_for_rule("K8S001") == "security"
    assert category_for_rule("K8S023") == "resource_management"
    assert category_for_rule("K8S020") == "observability"
    assert category_for_rule("K8S025") == "availability"
    assert category_for_rule("K8S041") == "networking"
    assert category_for_rule("K8S070") == "reliability"
    # Unknown ids default to security.
    assert category_for_rule("K8S999") == "security"


def test_not_applicable_without_k8s() -> None:
    score = assess_k8s([], has_k8s=False)
    assert score.applicable is False
    assert score.overall == 100


def test_all_six_dimensions_present() -> None:
    score = assess_k8s([], has_k8s=True)
    keys = {c.key for c in score.categories}
    assert keys == {key for key, _, _ in K8S_CATEGORIES}
    assert score.applicable is True
    assert score.overall == 100  # no findings -> perfect


def test_findings_reduce_the_relevant_dimension() -> None:
    findings = [
        {"rule_id": "K8S001", "severity": "high", "confidence": "high"},
        {"rule_id": "K8S023", "severity": "medium", "confidence": "high"},
    ]
    score = assess_k8s(findings, has_k8s=True)
    cats = {c.key: c for c in score.categories}
    assert cats["security"].score < 100
    assert cats["resource_management"].score < 100
    assert cats["networking"].score == 100  # untouched
    assert score.overall < 100


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


def test_kubernetes_score_endpoint_applicable(client: TestClient) -> None:
    scan_id = _upload(client, {"k8s/deploy.yaml": EXPOSED_NO_NETPOL})
    body = client.get(f"/api/v1/scans/{scan_id}/kubernetes-score").json()
    assert body["applicable"] is True
    assert 0 <= body["overall"] <= 100
    keys = {c["key"] for c in body["categories"]}
    assert keys == {key for key, _, _ in K8S_CATEGORIES}


def test_kubernetes_score_not_applicable_without_manifests(client: TestClient) -> None:
    scan_id = _upload(client, {"Dockerfile": "FROM ubuntu:24.04\nUSER 1000\n"})
    body = client.get(f"/api/v1/scans/{scan_id}/kubernetes-score").json()
    assert body["applicable"] is False
    assert body["overall"] == 100
