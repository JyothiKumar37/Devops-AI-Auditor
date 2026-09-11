"""Discovery vocabulary: categories, detected types and their mapping.

`FileCategory` values are exactly the keys used in the structured discovery
output. `DetectedType` is a finer-grained label stored per file; each detected
type maps to exactly one category.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FileCategory(str, Enum):
    """Top-level artifact categories (the keys of the grouped output)."""

    DOCKER = "docker"
    COMPOSE = "compose"
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"
    CICD = "cicd"
    HELM = "helm"
    ANSIBLE = "ansible"
    SHELL = "shell"
    CONFIGURATION = "configuration"
    OTHER = "other"


class DetectedType(str, Enum):
    """Fine-grained per-file classification labels (stored as file_type)."""

    DOCKERFILE = "dockerfile"
    DOCKER_COMPOSE = "docker_compose"
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    HELM_CHART = "helm_chart"
    HELM_VALUES = "helm_values"
    HELM_TEMPLATE = "helm_template"
    ANSIBLE_PLAYBOOK = "ansible_playbook"
    ANSIBLE_ROLE = "ansible_role"
    ANSIBLE_INVENTORY = "ansible_inventory"
    ANSIBLE_CONFIG = "ansible_config"
    SHELL = "shell"
    YAML = "yaml"
    JSON = "json"
    TOML = "toml"
    XML = "xml"
    ENV = "env"
    INI = "ini"
    CONFIG = "config"
    OTHER = "other"


# Each detected type belongs to exactly one category.
CATEGORY_BY_TYPE: dict[str, FileCategory] = {
    DetectedType.DOCKERFILE.value: FileCategory.DOCKER,
    DetectedType.DOCKER_COMPOSE.value: FileCategory.COMPOSE,
    DetectedType.KUBERNETES.value: FileCategory.KUBERNETES,
    DetectedType.TERRAFORM.value: FileCategory.TERRAFORM,
    DetectedType.GITHUB_ACTIONS.value: FileCategory.CICD,
    DetectedType.GITLAB_CI.value: FileCategory.CICD,
    DetectedType.JENKINS.value: FileCategory.CICD,
    DetectedType.HELM_CHART.value: FileCategory.HELM,
    DetectedType.HELM_VALUES.value: FileCategory.HELM,
    DetectedType.HELM_TEMPLATE.value: FileCategory.HELM,
    DetectedType.ANSIBLE_PLAYBOOK.value: FileCategory.ANSIBLE,
    DetectedType.ANSIBLE_ROLE.value: FileCategory.ANSIBLE,
    DetectedType.ANSIBLE_INVENTORY.value: FileCategory.ANSIBLE,
    DetectedType.ANSIBLE_CONFIG.value: FileCategory.ANSIBLE,
    DetectedType.SHELL.value: FileCategory.SHELL,
    DetectedType.YAML.value: FileCategory.CONFIGURATION,
    DetectedType.JSON.value: FileCategory.CONFIGURATION,
    DetectedType.TOML.value: FileCategory.CONFIGURATION,
    DetectedType.XML.value: FileCategory.CONFIGURATION,
    DetectedType.ENV.value: FileCategory.CONFIGURATION,
    DetectedType.INI.value: FileCategory.CONFIGURATION,
    DetectedType.CONFIG.value: FileCategory.CONFIGURATION,
    DetectedType.OTHER.value: FileCategory.OTHER,
}


def category_for(detected_type: str) -> FileCategory:
    """Return the category for a detected type, defaulting to OTHER."""
    return CATEGORY_BY_TYPE.get(detected_type, FileCategory.OTHER)


@dataclass(frozen=True, slots=True)
class DiscoveredFile:
    """A single classified repository file."""

    path: str
    detected_type: str
    category: FileCategory
    size: int
    checksum: str


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """The full result of a repository discovery run."""

    files: list[DiscoveredFile] = field(default_factory=list)

    def grouped(self) -> dict[str, list[str]]:
        """Return {category: [paths]} for every category (empty lists included)."""
        groups: dict[str, list[str]] = {c.value: [] for c in FileCategory}
        for item in self.files:
            groups[item.category.value].append(item.path)
        return groups

    def counts(self) -> dict[str, int]:
        """Return {category: file_count} for every category."""
        return {category: len(paths) for category, paths in self.grouped().items()}
