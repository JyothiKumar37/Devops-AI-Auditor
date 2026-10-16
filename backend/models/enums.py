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


class SuppressionReason(str, Enum):
    """Why a finding was suppressed (baselined) by a user."""

    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    WONT_FIX = "wont_fix"


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


# ---------------------------------------------------------------------------
# Phase 5: continuous security operations & incident response
# ---------------------------------------------------------------------------


class SecurityEventSourceType(str, Enum):
    """Where a normalized security event originated.

    Internal sources (repo/cloud scans, cloud changes) are produced by this
    platform's own deterministic engines and are therefore independently
    verified. External sources are reported by third parties and are treated as
    untrusted until corroborated by a deterministic check.
    """

    # Internal (independently verified by our deterministic engines)
    REPO_SCAN = "repo_scan"
    CLOUD_SCAN = "cloud_scan"
    CLOUD_CHANGE = "cloud_change"
    # AWS native (externally reported; ingested via API/fixtures)
    CLOUDTRAIL = "cloudtrail"
    GUARDDUTY = "guardduty"
    SECURITY_HUB = "security_hub"
    CONFIG = "aws_config"
    # Kubernetes / runtime
    K8S_AUDIT = "k8s_audit"
    FALCO = "falco"
    # Pipeline / monitoring (webhook delivered)
    CICD = "cicd"
    ALERTMANAGER = "alertmanager"


class SecurityEventCategory(str, Enum):
    """Coarse classification of a security event for correlation + display."""

    MISCONFIGURATION = "misconfiguration"
    EXPOSURE = "exposure"
    IDENTITY = "identity"
    THREAT = "threat"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    DRIFT = "drift"
    PIPELINE = "pipeline"
    RUNTIME = "runtime"
    OTHER = "other"


class SecurityEventStatus(str, Enum):
    """Processing lifecycle of a normalized event."""

    NEW = "new"
    CORRELATED = "correlated"
    IGNORED = "ignored"


class IncidentStatus(str, Enum):
    """Incident lifecycle. Transitions are validated on the backend."""

    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    CONTAINMENT_PLANNED = "containment_planned"
    CONTAINMENT_APPROVED = "containment_approved"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class ContainmentStatus(str, Enum):
    """Lifecycle of a remediation/containment plan."""

    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    VERIFIED = "verified"


class ContainmentCapability(str, Enum):
    """Capability class a containment action requires.

    READ/PLAN are always safe. WRITE actions mutate infrastructure and are gated
    behind ``cloud_write_enabled`` AND explicit human approval.
    """

    READ = "read"
    PLAN = "plan"
    WRITE = "write"
