"""Deterministic root-cause clustering of findings.

Groups a scan's findings into themed clusters (e.g. "Kubernetes resource &
reliability management") using the scanner + category + shared-file signals that
the deterministic engine already produces. This gives the AI structured
relationship data to reason over. The grouping itself is deterministic and
reproducible; any narrative the AI builds on top is labeled AI-inferred.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from models.enums import Severity
from models.finding import Finding

# (scanner, category) -> human theme. Falls back to a category theme.
_THEME_BY_SCANNER: dict[str, str] = {
    "kubernetes-rules": "Kubernetes workload configuration",
    "kubeconform": "Kubernetes workload configuration",
    "kubelinter": "Kubernetes workload configuration",
    "helm-rules": "Kubernetes/Helm configuration",
    "docker-rules": "Container image hardening",
    "compose-rules": "Container/Compose configuration",
    "hadolint": "Container image hardening",
    "trivy": "Container/vulnerability exposure",
    "terraform-rules": "Terraform infrastructure configuration",
    "tflint": "Terraform infrastructure configuration",
    "checkov": "Terraform infrastructure configuration",
    "secret-scanner": "Secret exposure",
    "github-actions-rules": "CI/CD pipeline security",
    "gitlab-ci-rules": "CI/CD pipeline security",
    "jenkins-rules": "CI/CD pipeline security",
    "actionlint": "CI/CD pipeline security",
    "dependency-scanner": "Dependency & supply-chain risk",
    "ansible-rules": "Ansible configuration",
    "config-rules": "Configuration management",
}

_THEME_BY_CATEGORY: dict[str, str] = {
    "security": "Security exposure",
    "secrets": "Secret exposure",
    "reliability": "Reliability & resource management",
    "efficiency": "Efficiency & resource usage",
    "supply_chain": "Dependency & supply-chain risk",
    "configuration": "Configuration management",
    "best_practice": "Best-practice gaps",
}


def _v(enum_or_str: Any) -> str:
    return enum_or_str.value if hasattr(enum_or_str, "value") else str(enum_or_str)


def _theme(scanner: str, category: str) -> str:
    if category == "reliability" and scanner.startswith("kubernetes"):
        return "Kubernetes resource & reliability management"
    return _THEME_BY_SCANNER.get(scanner) or _THEME_BY_CATEGORY.get(category) or "Other"


@dataclass(slots=True)
class RootCauseGroup:
    theme: str
    finding_ids: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.finding_ids)

    def _weight(self) -> int:
        return sum(Severity(s).rank * n for s, n in self.severity_counts.items())

    def to_dict(self) -> dict[str, Any]:
        return {
            "theme": self.theme,
            "count": self.count,
            "finding_ids": self.finding_ids,
            "rule_ids": sorted(set(self.rule_ids)),
            "files": sorted(set(f for f in self.files if f)),
            "severity_counts": self.severity_counts,
        }


def group_findings(findings_with_paths: list[tuple[Finding, str | None]]) -> list[RootCauseGroup]:
    """Cluster findings into deterministic, themed root-cause groups (desc by impact)."""
    groups: dict[str, RootCauseGroup] = defaultdict(lambda: RootCauseGroup(theme=""))
    for finding, path in findings_with_paths:
        theme = _theme(finding.scanner, _v(finding.category))
        group = groups[theme]
        group.theme = theme
        group.finding_ids.append(str(finding.id))
        group.rule_ids.append(finding.rule_id)
        if path:
            group.files.append(path)
        sev = _v(finding.severity)
        group.severity_counts[sev] = group.severity_counts.get(sev, 0) + 1
    ordered = sorted(groups.values(), key=lambda g: (-g._weight(), -g.count))
    return ordered
