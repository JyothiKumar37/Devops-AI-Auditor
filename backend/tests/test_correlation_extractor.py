"""Tests for the cross-stack entity extractor."""

from __future__ import annotations

from pathlib import Path

from scanners.correlation import CorrelationExtractor


def _write(root: Path, rel: str, content: str) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def test_extractor_builds_cross_stack_index(tmp_path: Path) -> None:
    _write(
        tmp_path, "infra/main.tf",
        'resource "aws_db_instance" "main" {\n  engine = "postgres"\n'
        "  publicly_accessible = true\n}\n"
        'resource "aws_eks_cluster" "prod" {\n  name = "prod"\n}\n',
    )
    _write(
        tmp_path, "k8s/deploy.yaml",
        "apiVersion: apps/v1\nkind: Deployment\n"
        "metadata:\n  name: api\n  namespace: staging\n"
        "spec:\n  template:\n    spec:\n      containers:\n"
        "        - name: api\n          image: myapp:latest\n"
        "          env:\n            - name: DATABASE_URL\n"
        "              value: db.abc.rds.amazonaws.com\n"
        "          envFrom:\n            - secretRef:\n                name: app-secrets\n",
    )
    _write(
        tmp_path, "k8s/service.yaml",
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: api\n  namespace: staging\n"
        "spec:\n  selector:\n    app: api\n  ports:\n    - port: 80\n",
    )
    _write(
        tmp_path, ".github/workflows/deploy.yml",
        "on: push\njobs:\n  deploy:\n    steps:\n"
        "      - run: docker build -t app .\n"
        "      - run: kubectl apply -n production -f k8s/\n",
    )

    files = [
        ("infra/main.tf", "terraform"),
        ("k8s/deploy.yaml", "kubernetes"),
        ("k8s/service.yaml", "kubernetes"),
        (".github/workflows/deploy.yml", "github_actions"),
    ]
    index = CorrelationExtractor().extract(tmp_path, files)

    # Terraform
    assert any(db["publicly_accessible"] for db in index["tf_databases"])
    assert index["eks_clusters"][0]["name"] == "prod"

    # Kubernetes
    workload = index["k8s_workloads"][0]
    assert workload["namespace"] == "staging"
    assert workload["images"] == ["myapp:latest"]
    assert workload["db_hosts"]  # DATABASE_URL / rds host captured
    assert "app-secrets" in workload["secret_refs"]
    assert index["k8s_services"][0]["name"] == "api"
    assert "staging" in index["k8s_namespaces"]

    # CI/CD
    cicd = index["cicd"]
    assert cicd["has_kubectl"] is True
    assert cicd["has_image_build"] is True
    assert "production" in cicd["deploy_namespaces"]


def test_extractor_ignores_templated_namespaces(tmp_path: Path) -> None:
    _write(
        tmp_path, ".gitlab-ci.yml",
        "deploy:\n  script:\n    - kubectl apply -n $CI_ENVIRONMENT -f k8s/\n",
    )
    index = CorrelationExtractor().extract(tmp_path, [(".gitlab-ci.yml", "gitlab_ci")])
    assert index["cicd"]["deploy_namespaces"] == []  # templated value skipped


def test_extractor_handles_empty(tmp_path: Path) -> None:
    index = CorrelationExtractor().extract(tmp_path, [])
    assert index["tf_databases"] == []
    assert index["k8s_workloads"] == []
