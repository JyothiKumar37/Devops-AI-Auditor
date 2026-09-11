"""Enumerations shared across the domain.

`ScannerType` enumerates every artifact class the auditor is designed to support.
The concrete scanners are intentionally NOT implemented in this foundation stage;
the enum documents the target scope and gives later stages a stable vocabulary.
"""

from __future__ import annotations

from enum import Enum


class SourceType(str, Enum):
    """How a repository was provided to the auditor."""

    ZIP = "zip"
    LOCAL = "local"
    GIT = "git"


class ScanStatus(str, Enum):
    """Lifecycle states of an audit job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    """Severity levels for findings, ordered from lowest to highest impact."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank (higher = more severe) for sorting and comparison."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    """How confident a scanner is that a finding is a true positive."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingCategory(str, Enum):
    """The class of issue a finding represents."""

    SECURITY = "security"
    SECRETS = "secrets"
    BEST_PRACTICE = "best_practice"
    RELIABILITY = "reliability"
    EFFICIENCY = "efficiency"
    SUPPLY_CHAIN = "supply_chain"
    CONFIGURATION = "configuration"


class ScannerType(str, Enum):
    """Artifact categories the auditor is designed to analyse."""

    DOCKERFILE = "dockerfile"
    DOCKER_COMPOSE = "docker_compose"
    KUBERNETES = "kubernetes"
    HELM = "helm"
    TERRAFORM = "terraform"
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    SHELL = "shell"
    ANSIBLE = "ansible"
    CONFIG = "config"
    SECRETS = "secrets"
