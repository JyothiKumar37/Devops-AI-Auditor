"""Deterministic, rule-based file classification.

Given a repository-relative path and (optionally) the file's content plus
repository context, returns a fine-grained `DetectedType`. No machine learning or
LLM is used - every decision is a reproducible rule. Content is only consulted to
distinguish Kubernetes manifests (which are otherwise ordinary YAML/JSON).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath

import yaml

from agents.discovery.types import DetectedType

# Kubernetes object kinds we recognise (spec list plus common additions).
_K8S_KINDS: frozenset[str] = frozenset(
    {
        "Deployment",
        "Service",
        "Ingress",
        "ConfigMap",
        "Secret",
        "StatefulSet",
        "DaemonSet",
        "Job",
        "CronJob",
        "HorizontalPodAutoscaler",
        "PodDisruptionBudget",
        "Role",
        "ClusterRole",
        "RoleBinding",
        "ClusterRoleBinding",
        "ServiceAccount",
        "PersistentVolumeClaim",
        "NetworkPolicy",
        # Common additional kinds.
        "Pod",
        "ReplicaSet",
        "Namespace",
        "PersistentVolume",
        "StorageClass",
        "CustomResourceDefinition",
        "ReplicationController",
        "Endpoints",
        "LimitRange",
        "ResourceQuota",
    }
)

_K8S_API_VERSIONS: frozenset[str] = frozenset(
    {
        "v1",
        "apps/v1",
        "batch/v1",
        "batch/v1beta1",
        "autoscaling/v1",
        "autoscaling/v2",
        "autoscaling/v2beta2",
        "policy/v1",
        "policy/v1beta1",
    }
)

_YAML_SUFFIXES = {".yml", ".yaml"}
_ANSIBLE_ROLE_DIRS = {"tasks", "handlers", "defaults", "vars", "meta", "templates", "files"}
_MAX_CONTENT_FOR_YAML = 1024 * 1024  # only parse reasonably sized files


@dataclass(frozen=True, slots=True)
class DiscoveryContext:
    """Repository-level context used for path-relative decisions.

    Attributes:
        chart_dirs: POSIX directory paths that contain a Chart.yaml (a "" entry
            denotes a chart rooted at the repository root).
    """

    chart_dirs: frozenset[str] = field(default_factory=frozenset)


def _is_kubernetes_manifest(content: bytes | None) -> bool:
    """Return True if content parses as one or more Kubernetes objects."""
    if not content or len(content) > _MAX_CONTENT_FOR_YAML:
        return False
    text = content.decode("utf-8", errors="ignore")
    if "apiVersion" not in text or "kind" not in text:
        return False
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return False

    for doc in documents:
        if not isinstance(doc, dict):
            continue
        api_version = doc.get("apiVersion")
        kind = doc.get("kind")
        if not isinstance(api_version, str) or not isinstance(kind, str):
            continue
        if kind in _K8S_KINDS:
            return True
        if api_version in _K8S_API_VERSIONS or "k8s.io" in api_version:
            return True
    return False


def _within_chart_templates(rel_path: str, context: DiscoveryContext) -> bool:
    for chart_dir in context.chart_dirs:
        prefix = "templates/" if chart_dir == "" else f"{chart_dir}/templates/"
        if rel_path.startswith(prefix):
            return True
    return False


def classify_file(
    relative_path: str,
    *,
    content: bytes | None = None,
    context: DiscoveryContext | None = None,
) -> str:
    """Classify a repository-relative POSIX path into a DetectedType value."""
    context = context or DiscoveryContext()
    path = PurePosixPath(relative_path)
    name = path.name
    lower = name.lower()
    suffix = path.suffix.lower()
    parts = path.parts
    lower_parts = [p.lower() for p in parts]

    # 1. Dockerfiles
    if lower == "dockerfile" or lower.startswith("dockerfile.") or suffix == ".dockerfile":
        return DetectedType.DOCKERFILE.value

    # 2. Docker Compose
    if lower in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        return DetectedType.DOCKER_COMPOSE.value

    # 3. CI/CD
    if suffix in _YAML_SUFFIXES and ".github" in lower_parts and "workflows" in lower_parts:
        return DetectedType.GITHUB_ACTIONS.value
    if lower in {".gitlab-ci.yml", ".gitlab-ci.yaml"}:
        return DetectedType.GITLAB_CI.value
    if lower == "jenkinsfile" or lower.startswith("jenkinsfile.") or suffix == ".jenkinsfile":
        return DetectedType.JENKINS.value

    # 4. Terraform
    if suffix in {".tf", ".tfvars"} or lower.endswith(".tf.json"):
        return DetectedType.TERRAFORM.value

    # 5. Helm (name-based charts/values; templates by chart context)
    if lower in {"chart.yaml", "chart.yml"}:
        return DetectedType.HELM_CHART.value
    if lower in {"values.yaml", "values.yml"}:
        return DetectedType.HELM_VALUES.value
    if _within_chart_templates(relative_path, context):
        return DetectedType.HELM_TEMPLATE.value

    # 6. Kubernetes (content-aware; must precede generic YAML/JSON)
    if (suffix in _YAML_SUFFIXES or suffix == ".json") and _is_kubernetes_manifest(content):
        return DetectedType.KUBERNETES.value

    # 7. Ansible
    ansible_type = _classify_ansible(lower, suffix, lower_parts)
    if ansible_type is not None:
        return ansible_type

    # 8. Shell scripts
    if suffix in {".sh", ".bash"}:
        return DetectedType.SHELL.value

    # 9. Generic configuration by extension
    if suffix in _YAML_SUFFIXES:
        return DetectedType.YAML.value
    if suffix == ".json":
        return DetectedType.JSON.value
    if suffix == ".toml":
        return DetectedType.TOML.value
    if suffix == ".xml":
        return DetectedType.XML.value
    if lower == ".env" or lower.startswith(".env."):
        return DetectedType.ENV.value
    if suffix == ".ini":
        return DetectedType.INI.value
    if suffix in {".cfg", ".conf", ".config", ".properties"}:
        return DetectedType.CONFIG.value

    return DetectedType.OTHER.value


def _classify_ansible(lower: str, suffix: str, lower_parts: list[str]) -> str | None:
    """Heuristic, deterministic Ansible detection."""
    if lower == "ansible.cfg":
        return DetectedType.ANSIBLE_CONFIG.value

    # roles/<role>/<tasks|handlers|defaults|vars|meta|templates|files>/...
    if "roles" in lower_parts and suffix in _YAML_SUFFIXES:
        idx = lower_parts.index("roles")
        # role subdir is two levels below "roles" (roles/<role>/<subdir>/...)
        if len(lower_parts) > idx + 2 and lower_parts[idx + 2] in _ANSIBLE_ROLE_DIRS:
            return DetectedType.ANSIBLE_ROLE.value

    if suffix in _YAML_SUFFIXES and (
        lower in {"site.yml", "site.yaml", "playbook.yml", "playbook.yaml"}
        or lower.startswith("playbook")
        or "playbooks" in lower_parts
    ):
        return DetectedType.ANSIBLE_PLAYBOOK.value

    # Inventory files: named inventory/hosts, or living under an inventory dir.
    if lower in {"inventory", "hosts", "inventory.ini", "hosts.ini"}:
        return DetectedType.ANSIBLE_INVENTORY.value
    if "inventory" in lower_parts and suffix in {".ini", ".yml", ".yaml", ""}:
        return DetectedType.ANSIBLE_INVENTORY.value

    return None


class FileClassifier:
    """Convenience wrapper binding a `DiscoveryContext` for repeated calls."""

    def __init__(self, context: DiscoveryContext | None = None) -> None:
        self._context = context or DiscoveryContext()

    @property
    def context(self) -> DiscoveryContext:
        return self._context

    def classify(self, relative_path: str, content: bytes | None = None) -> str:
        return classify_file(relative_path, content=content, context=self._context)
