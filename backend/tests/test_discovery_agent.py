"""Tests for the RepositoryDiscoveryAgent against a real directory tree."""

from __future__ import annotations

from pathlib import Path

from agents.discovery.agent import RepositoryDiscoveryAgent


def _write(root: Path, rel: str, content: bytes = b"x\n") -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)


def _sample_repo(root: Path) -> None:
    _write(root, "Dockerfile", b"FROM alpine\n")
    _write(root, "docker-compose.yml", b"services: {}\n")
    _write(root, ".github/workflows/ci.yml", b"name: ci\non: push\n")
    _write(root, "Jenkinsfile", b"pipeline {}\n")
    _write(root, "infra/main.tf", b'resource "x" "y" {}\n')
    _write(root, "scripts/deploy.sh", b"#!/bin/sh\necho hi\n")
    _write(
        root,
        "k8s/deployment.yaml",
        b"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
    )
    _write(root, "charts/web/Chart.yaml", b"apiVersion: v2\nname: web\nversion: 0.1.0\n")
    _write(root, "charts/web/values.yaml", b"replicas: 1\n")
    _write(
        root,
        "charts/web/templates/deployment.yaml",
        b"apiVersion: apps/v1\nkind: Deployment\n",
    )
    _write(root, "roles/web/tasks/main.yml", b"- name: task\n")
    _write(root, "config/app.toml", b"[server]\nport = 8080\n")
    _write(root, "README.md", b"# demo\n")


def test_discover_groups_all_categories(tmp_path: Path) -> None:
    _sample_repo(tmp_path)

    result = RepositoryDiscoveryAgent().discover(tmp_path)
    grouped = result.grouped()

    assert "Dockerfile" in grouped["docker"]
    assert "docker-compose.yml" in grouped["compose"]
    assert grouped["kubernetes"] == ["k8s/deployment.yaml"]
    assert "infra/main.tf" in grouped["terraform"]
    assert set(grouped["cicd"]) == {".github/workflows/ci.yml", "Jenkinsfile"}
    assert set(grouped["helm"]) == {
        "charts/web/Chart.yaml",
        "charts/web/values.yaml",
        "charts/web/templates/deployment.yaml",
    }
    assert grouped["ansible"] == ["roles/web/tasks/main.yml"]
    assert "scripts/deploy.sh" in grouped["shell"]
    assert "config/app.toml" in grouped["configuration"]
    assert "README.md" in grouped["other"]


def test_discover_computes_checksums_and_sizes(tmp_path: Path) -> None:
    _write(tmp_path, "Dockerfile", b"FROM alpine\n")

    result = RepositoryDiscoveryAgent().discover(tmp_path)

    assert len(result.files) == 1
    dockerfile = result.files[0]
    assert dockerfile.size == len(b"FROM alpine\n")
    assert len(dockerfile.checksum) == 64
    assert dockerfile.detected_type == "dockerfile"


def test_discover_counts_include_every_category(tmp_path: Path) -> None:
    _write(tmp_path, "Dockerfile", b"FROM alpine\n")

    counts = RepositoryDiscoveryAgent().discover(tmp_path).counts()

    # Every category key is present even when empty.
    assert set(counts) == {
        "docker",
        "compose",
        "kubernetes",
        "terraform",
        "cicd",
        "helm",
        "ansible",
        "shell",
        "configuration",
        "other",
    }
    assert counts["docker"] == 1
