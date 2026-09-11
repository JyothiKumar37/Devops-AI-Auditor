"""Tests for the deterministic discovery classifier."""

from __future__ import annotations

import pytest

from agents.discovery.classifier import DiscoveryContext, classify_file
from agents.discovery.types import FileCategory, category_for


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        # Docker
        ("Dockerfile", "dockerfile"),
        ("service/Dockerfile", "dockerfile"),
        ("Dockerfile.prod", "dockerfile"),
        ("api.dockerfile", "dockerfile"),
        # Compose
        ("docker-compose.yml", "docker_compose"),
        ("docker-compose.yaml", "docker_compose"),
        ("compose.yml", "docker_compose"),
        ("compose.yaml", "docker_compose"),
        # CI/CD
        (".github/workflows/ci.yml", "github_actions"),
        (".github/workflows/release.yaml", "github_actions"),
        (".gitlab-ci.yml", "gitlab_ci"),
        ("Jenkinsfile", "jenkins"),
        ("Jenkinsfile.release", "jenkins"),
        # Terraform
        ("infra/main.tf", "terraform"),
        ("infra/variables.tfvars", "terraform"),
        ("infra/main.tf.json", "terraform"),
        # Shell
        ("scripts/deploy.sh", "shell"),
        ("run.bash", "shell"),
        # Generic configuration
        ("config/app.toml", "toml"),
        ("config/settings.json", "json"),
        ("config/logging.yaml", "yaml"),
        ("pom.xml", "xml"),
        (".env", "env"),
        (".env.production", "env"),
        ("setup.ini", "ini"),
        ("nginx.conf", "config"),
        # Other
        ("src/main.py", "other"),
        ("README.md", "other"),
    ],
)
def test_classify_path_based(path: str, expected: str) -> None:
    assert classify_file(path) == expected


def test_kubernetes_detected_by_content() -> None:
    manifest = b"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 2
"""
    assert classify_file("k8s/deploy.yaml", content=manifest) == "kubernetes"


def test_kubernetes_multiple_kinds() -> None:
    for kind, api in [
        ("Service", "v1"),
        ("Ingress", "networking.k8s.io/v1"),
        ("CronJob", "batch/v1"),
        ("HorizontalPodAutoscaler", "autoscaling/v2"),
        ("NetworkPolicy", "networking.k8s.io/v1"),
        ("ServiceAccount", "v1"),
        ("PersistentVolumeClaim", "v1"),
    ]:
        content = f"apiVersion: {api}\nkind: {kind}\nmetadata:\n  name: x\n".encode()
        assert classify_file("manifest.yaml", content=content) == "kubernetes", kind


def test_plain_yaml_is_not_kubernetes() -> None:
    content = b"name: my-app\nversion: 1\nsettings:\n  debug: true\n"
    assert classify_file("config/app.yaml", content=content) == "yaml"


def test_kubernetes_requires_content() -> None:
    # Without content, a generic manifest name falls back to YAML.
    assert classify_file("k8s/deploy.yaml") == "yaml"


def test_helm_detection() -> None:
    ctx = DiscoveryContext(chart_dirs=frozenset({"charts/web"}))
    assert classify_file("charts/web/Chart.yaml") == "helm_chart"
    assert classify_file("charts/web/values.yaml") == "helm_values"
    assert classify_file("charts/web/templates/deployment.yaml", context=ctx) == "helm_template"
    # A helm template is classified as helm even though it looks like k8s YAML.
    k8s_like = b"apiVersion: apps/v1\nkind: Deployment\n"
    assert (
        classify_file("charts/web/templates/deployment.yaml", content=k8s_like, context=ctx)
        == "helm_template"
    )


def test_ansible_detection() -> None:
    assert classify_file("ansible.cfg") == "ansible_config"
    assert classify_file("playbooks/site.yml") == "ansible_playbook"
    assert classify_file("site.yml") == "ansible_playbook"
    assert classify_file("roles/web/tasks/main.yml") == "ansible_role"
    assert classify_file("roles/web/handlers/main.yaml") == "ansible_role"
    assert classify_file("inventory/hosts") == "ansible_inventory"
    assert classify_file("inventory.ini") == "ansible_inventory"


@pytest.mark.parametrize(
    ("detected", "category"),
    [
        ("dockerfile", FileCategory.DOCKER),
        ("docker_compose", FileCategory.COMPOSE),
        ("kubernetes", FileCategory.KUBERNETES),
        ("terraform", FileCategory.TERRAFORM),
        ("github_actions", FileCategory.CICD),
        ("gitlab_ci", FileCategory.CICD),
        ("jenkins", FileCategory.CICD),
        ("helm_chart", FileCategory.HELM),
        ("helm_template", FileCategory.HELM),
        ("ansible_playbook", FileCategory.ANSIBLE),
        ("shell", FileCategory.SHELL),
        ("yaml", FileCategory.CONFIGURATION),
        ("json", FileCategory.CONFIGURATION),
        ("env", FileCategory.CONFIGURATION),
        ("other", FileCategory.OTHER),
    ],
)
def test_category_mapping(detected: str, category: FileCategory) -> None:
    assert category_for(detected) == category
