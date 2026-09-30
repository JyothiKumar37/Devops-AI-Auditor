"""Deterministic security/DevOps posture scoring by domain.

The production-readiness engine gives one overall score built from eight
internal categories. The *posture* view re-projects the same findings onto the
nine product-facing domains the dashboard shows (security, infrastructure,
CI/CD, kubernetes, containers, terraform, reliability, secrets, dependencies)
and scores each 0-100.

Domains deliberately OVERLAP: a privileged Kubernetes container counts toward
both ``kubernetes`` and ``security`` because a user reasoning about either lens
should see it. Scores are never produced by an LLM - each is ``100 - penalty``
using the exact same severity/confidence penalty model as readiness
(``agents.reasoning.readiness.category_penalty``), so posture and readiness can
never disagree about how severe a finding is.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from agents.reasoning.readiness import category_penalty

# Product-facing domains, in display order (key, label).
POSTURE_DOMAINS: list[tuple[str, str]] = [
    ("security", "Security"),
    ("infrastructure", "Infrastructure"),
    ("cicd", "CI/CD"),
    ("kubernetes", "Kubernetes"),
    ("containers", "Containers"),
    ("terraform", "Terraform"),
    ("reliability", "Reliability"),
    ("secrets", "Secrets"),
    ("dependencies", "Dependencies"),
]
_DOMAIN_LABEL = dict(POSTURE_DOMAINS)

# Scanner -> the domains its findings contribute to.
_SCANNER_DOMAINS: dict[str, set[str]] = {
    "secret-scanner": {"secrets", "security"},
    "terraform-rules": {"terraform", "infrastructure"},
    "tflint": {"terraform", "infrastructure"},
    "checkov": {"terraform", "infrastructure"},
    "kubernetes-rules": {"kubernetes"},
    "kubeconform": {"kubernetes"},
    "kubelinter": {"kubernetes"},
    "docker-rules": {"containers"},
    "compose-rules": {"containers"},
    "hadolint": {"containers"},
    "trivy": {"containers"},
    "github-actions-rules": {"cicd"},
    "gitlab-ci-rules": {"cicd"},
    "jenkins-rules": {"cicd"},
    "actionlint": {"cicd"},
    "ansible-rules": {"infrastructure"},
    "helm-rules": {"kubernetes", "infrastructure"},
    "config-rules": {"infrastructure"},
    "dependency-scanner": {"dependencies", "security"},
}

# Finding category -> extra domains (cross-cutting lenses).
_CATEGORY_DOMAINS: dict[str, set[str]] = {
    "security": {"security"},
    "secrets": {"secrets", "security"},
    "reliability": {"reliability"},
    "supply_chain": {"dependencies", "security"},
}

# Domains that always apply (these scanners/lenses run against every repo).
_ALWAYS_APPLICABLE = {"security", "reliability", "secrets"}

# File types that make a domain applicable.
_APPLICABLE_BY_FILETYPE: dict[str, set[str]] = {
    "kubernetes": {"kubernetes", "helm_chart", "helm_values", "helm_template"},
    "containers": {"dockerfile", "docker_compose"},
    "terraform": {"terraform"},
    "cicd": {"github_actions", "gitlab_ci", "jenkins"},
    "infrastructure": {
        "terraform", "ansible_playbook", "ansible_role", "ansible_inventory",
        "ansible_config", "helm_chart", "helm_values", "helm_template",
        "kubernetes", "yaml", "json", "toml", "ini", "env", "config",
    },
}


@dataclass(frozen=True, slots=True)
class DomainScore:
    """A single posture domain's deterministic score."""

    key: str
    label: str
    score: int
    applicable: bool
    findings: int
    counts: dict[str, int] = field(default_factory=dict)
    explanation: str = ""


def domains_for(finding: dict[str, Any]) -> set[str]:
    """Return every posture domain a finding contributes to (may be several)."""
    scanner = str(finding.get("scanner", ""))
    category = str(finding.get("category", ""))
    domains: set[str] = set()
    domains |= _SCANNER_DOMAINS.get(scanner, set())
    domains |= _CATEGORY_DOMAINS.get(category, set())
    return domains


def _applicable(domain: str, file_types: set[str], has_findings: bool) -> bool:
    if domain in _ALWAYS_APPLICABLE:
        return True
    if domain == "dependencies":
        # Only claim a dependency posture once real dependency findings exist
        # (SBOM/dependency scanning is a later milestone) - never fabricate one.
        return has_findings
    wanted = _APPLICABLE_BY_FILETYPE.get(domain, set())
    return has_findings or bool(file_types & wanted)


def assess_posture(
    findings: list[dict[str, Any]], files: list[dict[str, Any]]
) -> list[DomainScore]:
    """Compute the per-domain posture scores from deterministic findings."""
    file_types = {str(f.get("file_type")) for f in files}

    by_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        for domain in domains_for(finding):
            by_domain[domain].append(finding)

    scores: list[DomainScore] = []
    for key, label in POSTURE_DOMAINS:
        members = by_domain.get(key, [])
        counts: dict[str, int] = defaultdict(int)
        for f in members:
            counts[str(f.get("severity", "info"))] += 1
        penalty = category_penalty(members)
        score = max(0, min(100, round(100 - penalty)))
        applicable = _applicable(key, file_types, bool(members))
        scores.append(
            DomainScore(
                key=key,
                label=label,
                score=score if applicable else 100,
                applicable=applicable,
                findings=len(members),
                counts=dict(counts),
                explanation=_explain(label, members, dict(counts), penalty, score, applicable),
            )
        )
    return scores


def _explain(
    label: str,
    members: list[dict[str, Any]],
    counts: dict[str, int],
    penalty: float,
    score: int,
    applicable: bool,
) -> str:
    if not applicable:
        return f"No {label.lower()} artifacts detected; not applicable to this repository."
    if not members:
        return f"No {label.lower()} findings; category at full score."
    parts = ", ".join(f"{n} {sev}" for sev, n in counts.items())
    return f"{len(members)} finding(s) ({parts}) → −{round(penalty)} points → {score}/100."
