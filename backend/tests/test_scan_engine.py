"""Tests for the pure, DB-free scan engine (shared by PR scan + CLI)."""

from __future__ import annotations

from pathlib import Path

from core.config import Settings
from services.scan_engine import scan_repository

VULN_DOCKERFILE = "FROM ubuntu:latest\nUSER root\n"
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
          image: myrepo/api:latest
          securityContext:
            privileged: true
"""


def _settings() -> Settings:
    return Settings(environment="development", llm_provider="none")


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


def test_scan_repository_full(tmp_path: Path) -> None:
    _write(tmp_path, {"Dockerfile": VULN_DOCKERFILE, "k8s/app.yaml": VULN_K8S})
    findings = scan_repository(tmp_path, _settings())
    scanners = {f.scanner for f in findings}
    assert "docker-rules" in scanners
    assert "kubernetes-rules" in scanners


def test_scan_repository_incremental_only_changed(tmp_path: Path) -> None:
    _write(tmp_path, {"Dockerfile": VULN_DOCKERFILE, "k8s/app.yaml": VULN_K8S})
    # Restrict to the Kubernetes manifest: no Docker findings should appear.
    findings = scan_repository(tmp_path, _settings(), only_paths={"k8s/app.yaml"})
    scanners = {f.scanner for f in findings}
    assert "kubernetes-rules" in scanners
    assert "docker-rules" not in scanners
    assert all(f.file_path == "k8s/app.yaml" for f in findings)


def test_scan_repository_empty(tmp_path: Path) -> None:
    _write(tmp_path, {"README.md": "# docs\n"})
    assert scan_repository(tmp_path, _settings()) == []
