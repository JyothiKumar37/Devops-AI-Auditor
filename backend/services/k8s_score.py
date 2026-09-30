"""Deterministic Kubernetes production-readiness scoring.

Projects the Kubernetes scanner's findings (rule ids ``K8Snnn``) onto six
production-readiness dimensions and scores each 0-100, plus a weighted overall
score. Reuses the shared severity/confidence penalty model
(``agents.reasoning.readiness.category_penalty``) so it can never disagree with
the other scorers about how much a finding hurts. No LLM is involved.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from agents.reasoning.readiness import category_penalty

# The six Kubernetes readiness dimensions (key, label, importance weight).
K8S_CATEGORIES: list[tuple[str, str, float]] = [
    ("security", "Security", 0.28),
    ("reliability", "Reliability", 0.16),
    ("availability", "Availability", 0.16),
    ("resource_management", "Resource Management", 0.14),
    ("networking", "Networking", 0.14),
    ("observability", "Observability", 0.12),
]
_LABEL = {key: label for key, label, _ in K8S_CATEGORIES}
_WEIGHT = {key: weight for key, _, weight in K8S_CATEGORIES}

# Explicit rule -> dimension mapping (deterministic; default is "security").
_RULE_CATEGORY: dict[str, str] = {
    # observability: probes
    "K8S020": "observability", "K8S021": "observability", "K8S022": "observability",
    # resource management: requests / limits
    "K8S023": "resource_management", "K8S024": "resource_management",
    # availability: replicas / disruption budget / autoscaling
    "K8S025": "availability", "K8S026": "availability", "K8S027": "availability",
    "K8S075": "availability", "K8S076": "availability",
    # networking: service exposure / policy / ingress
    "K8S040": "networking", "K8S041": "networking", "K8S042": "networking",
    "K8S043": "networking", "K8S044": "networking",
    # reliability: manifest validity + cross-file wiring correctness
    "K8S000": "reliability", "K8S070": "reliability", "K8S071": "reliability",
    "K8S072": "reliability", "K8S073": "reliability", "K8S074": "reliability",
    # everything else (K8S001-012 pod security, K8S030-032 image,
    # K8S050-053 RBAC, K8S060-062 secrets) -> security
}


def category_for_rule(rule_id: str) -> str:
    return _RULE_CATEGORY.get(rule_id, "security")


@dataclass(frozen=True, slots=True)
class K8sCategoryScore:
    key: str
    label: str
    score: int
    findings: int
    counts: dict[str, int] = field(default_factory=dict)
    explanation: str = ""


@dataclass(frozen=True, slots=True)
class K8sScore:
    applicable: bool
    overall: int
    total_findings: int
    categories: list[K8sCategoryScore] = field(default_factory=list)


def assess_k8s(findings: list[dict[str, Any]], *, has_k8s: bool) -> K8sScore:
    """Score Kubernetes readiness from the scan's ``kubernetes-rules`` findings.

    ``findings`` should already be limited to Kubernetes findings. ``has_k8s``
    indicates whether the repository actually contains Kubernetes manifests; when
    it does not, the score is reported as not-applicable (overall 100).
    """
    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        by_category[category_for_rule(str(finding.get("rule_id", "")))].append(finding)

    categories: list[K8sCategoryScore] = []
    weighted_sum = 0.0
    weight_total = 0.0
    for key, label, weight in K8S_CATEGORIES:
        members = by_category.get(key, [])
        counts: dict[str, int] = defaultdict(int)
        for f in members:
            counts[str(f.get("severity", "info"))] += 1
        penalty = category_penalty(members)
        score = max(0, min(100, round(100 - penalty)))
        categories.append(
            K8sCategoryScore(
                key=key,
                label=label,
                score=score,
                findings=len(members),
                counts=dict(counts),
                explanation=_explain(label, members, dict(counts), penalty, score),
            )
        )
        weighted_sum += score * weight
        weight_total += weight

    overall = round(weighted_sum / weight_total) if weight_total else 100
    if not has_k8s:
        return K8sScore(applicable=False, overall=100, total_findings=0, categories=categories)
    return K8sScore(
        applicable=True,
        overall=overall,
        total_findings=len(findings),
        categories=categories,
    )


def _explain(
    label: str,
    members: list[dict[str, Any]],
    counts: dict[str, int],
    penalty: float,
    score: int,
) -> str:
    if not members:
        return f"No {label.lower()} issues; dimension at full score."
    parts = ", ".join(f"{n} {sev}" for sev, n in counts.items())
    return f"{len(members)} finding(s) ({parts}) → −{round(penalty)} points → {score}/100."
