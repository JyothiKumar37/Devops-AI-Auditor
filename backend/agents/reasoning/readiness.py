"""Deterministic, explainable production-readiness scoring.

The score is computed purely from the deterministic findings - never asked of an
LLM. Each finding is assigned to one of eight readiness categories and penalises
that category by a weight that scales with severity (critical penalties are far
larger than informational ones) and the finding's confidence. Within a category
repeated findings of the same severity apply diminishing penalties (a bounded
geometric series), so a large volume of lower-severity issues cannot floor a
category to zero unless genuine critical issues are present. Category scores are
combined into an overall score using category importance weights, restricted to
the categories that actually apply to the repository.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from agents.reasoning.schemas import CategoryScore, ProductionReadiness
from models.enums import Confidence, Severity

# Penalty for the first finding of a severity - critical dominates.
_SEVERITY_PENALTY = {
    "critical": 45.0, "high": 22.0, "medium": 9.0, "low": 3.0, "info": 1.0,
}
# Diminishing-returns decay applied to each additional finding of the same
# severity within a category. The per-severity penalty is a geometric series
# (base + base*decay + base*decay^2 + ...) so it converges to a finite cap:
# many medium/low findings can no longer floor a category to 0 when there are
# no criticals. Criticals do not decay - each one is a genuine blocker.
_SEVERITY_DECAY = {
    "critical": 1.0, "high": 0.6, "medium": 0.55, "low": 0.5, "info": 0.4,
}
# Lower-confidence findings penalise less.
_CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.75, "low": 0.5}

# Category importance weights (sum to 1.0).
_CATEGORY_WEIGHT = {
    "security": 0.22,
    "reliability": 0.15,
    "kubernetes": 0.12,
    "containers": 0.12,
    "infrastructure": 0.12,
    "cicd": 0.09,
    "observability": 0.09,
    "maintainability": 0.09,
}
_CATEGORY_ORDER = list(_CATEGORY_WEIGHT)
_ALWAYS_APPLICABLE = {"security", "reliability", "observability", "maintainability"}

# Minimum score every applicable category must reach for the repo to be "ready".
# Prevents a high overall average from masking one badly failing core area.
_READY_CATEGORY_FLOOR = 50

# Health/probe rules represent observability rather than raw reliability.
_OBSERVABILITY_RULES = {"K8S020", "K8S021", "K8S022", "DCK012", "DCMP008"}
_SECURITY_CATEGORIES = {"security", "secrets", "supply_chain"}
_CONTAINER_SCANNERS = {"docker-rules", "compose-rules", "hadolint", "trivy"}
_INFRA_SCANNERS = {"terraform-rules", "tflint", "checkov", "kubeconform"}
_CICD_SCANNERS = {"github-actions-rules", "gitlab-ci-rules", "jenkins-rules", "actionlint"}


def _readiness_category(finding: dict[str, Any]) -> str:
    """Assign a finding to exactly one readiness category (deterministic)."""
    rule = finding.get("rule_id", "")
    scanner = finding.get("scanner", "")
    category = finding.get("category", "")

    if rule in _OBSERVABILITY_RULES:
        return "observability"
    if scanner == "secret-scanner" or category in _SECURITY_CATEGORIES:
        return "security"
    if category == "reliability":
        return "reliability"
    if scanner == "kubernetes-rules":
        return "kubernetes"
    if scanner in _CONTAINER_SCANNERS:
        return "containers"
    if scanner in _INFRA_SCANNERS:
        return "infrastructure"
    if scanner in _CICD_SCANNERS:
        return "cicd"
    return "maintainability"


def _applicable_categories(files: list[dict[str, Any]]) -> set[str]:
    types = {str(f.get("file_type")) for f in files}
    applicable = set(_ALWAYS_APPLICABLE)
    if types & {"kubernetes", "helm_chart", "helm_values", "helm_template"}:
        applicable.add("kubernetes")
    if types & {"dockerfile", "docker_compose"}:
        applicable.add("containers")
    if "terraform" in types:
        applicable.add("infrastructure")
    if types & {"github_actions", "gitlab_ci", "jenkins"}:
        applicable.add("cicd")
    return applicable


def _label(finding: dict[str, Any]) -> str:
    file = finding.get("file") or "?"
    return f"{finding['title']} — {file}"


def _sorted_by_risk(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda f: (
            Severity(f["severity"]).rank,
            _CONFIDENCE_FACTOR.get(f.get("confidence", "medium"), 0.75),
        ),
        reverse=True,
    )


def assess(findings: list[dict[str, Any]], files: list[dict[str, Any]]) -> ProductionReadiness:
    """Compute the production-readiness assessment from deterministic findings."""
    applicable = _applicable_categories(files)

    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        by_category[_readiness_category(finding)].append(finding)

    category_scores: list[CategoryScore] = []
    weighted_sum = 0.0
    weight_total = 0.0

    for category in _CATEGORY_ORDER:
        members = by_category.get(category, [])
        counts: dict[str, int] = defaultdict(int)
        for f in members:
            counts[f["severity"]] += 1
        penalty = _category_penalty(members)
        score = max(0, min(100, round(100 - penalty)))
        is_applicable = category in applicable
        explanation = _category_explanation(category, members, counts, penalty, score)
        category_scores.append(
            CategoryScore(
                category=category,
                score=score,
                weight=_CATEGORY_WEIGHT[category],
                applicable=is_applicable,
                findings=len(members),
                counts=dict(counts),
                explanation=explanation,
            )
        )
        if is_applicable:
            weighted_sum += score * _CATEGORY_WEIGHT[category]
            weight_total += _CATEGORY_WEIGHT[category]

    overall = round(weighted_sum / weight_total) if weight_total else 100

    critical = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]
    blockers = _dedupe([_label(f) for f in _sorted_by_risk(critical)])
    top_risks = _dedupe([_label(f) for f in _sorted_by_risk(high)])[:10]
    next_actions = _dedupe(
        [f.get("recommendation") or "" for f in _sorted_by_risk(critical + high) if
         f.get("recommendation")]
    )[:8]

    # A core area scoring far below the overall still blocks readiness even with
    # no criticals: a repo can average well yet be unshippable because (say)
    # Security is riddled with high-severity issues.
    weak = [
        (cs.category, cs.score)
        for cs in category_scores
        if cs.applicable and cs.score < _READY_CATEGORY_FLOOR
    ]
    weak.sort(key=lambda cs: cs[1])
    ready = not critical and overall >= 70 and not weak

    summary = (
        f"Production readiness: {overall}/100. "
        f"{'Ready' if ready else 'Not ready'} for production — "
        f"{len(critical)} critical, {len(high)} high severity findings."
    )
    if not critical and overall >= 70 and weak:
        category, cat_score = weak[0]
        summary += (
            f" Held back by the {category} category ({cat_score}/100, below the "
            f"{_READY_CATEGORY_FLOOR}-point readiness floor)."
        )
    explanation = (
        "Overall score is the weighted average of the applicable category scores "
        f"({', '.join(sorted(applicable))}). Each category starts at 100 and loses "
        "severity-weighted, confidence-adjusted points per finding (critical=45, "
        "high=22, medium=9, low=3, info=1). Repeated findings of the same severity "
        "apply diminishing penalties, so a large volume of lower-severity issues "
        "cannot drive a category to zero unless critical issues are present. A repo "
        f"is only 'ready' with no criticals, an overall score of 70+, and every "
        f"applicable category at or above {_READY_CATEGORY_FLOOR}/100."
    )

    return ProductionReadiness(
        ready=ready,
        score=overall,
        summary=summary,
        confidence=Confidence.HIGH,
        category_scores=category_scores,
        blockers=blockers,
        top_risks=top_risks,
        next_actions=next_actions,
        explanation=explanation,
    )


def _category_penalty(members: list[dict[str, Any]]) -> float:
    """Confidence-weighted penalty with per-severity diminishing returns.

    Within each severity the highest-confidence findings penalise at the full
    rate and each subsequent finding decays geometrically, so the total penalty
    a severity can contribute to a category is bounded. Criticals do not decay -
    each one is treated as a genuine production blocker.
    """
    by_severity: dict[str, list[float]] = defaultdict(list)
    for f in members:
        confidence = _CONFIDENCE_FACTOR.get(f.get("confidence", "medium"), 0.75)
        by_severity[f["severity"]].append(confidence)

    total = 0.0
    for sev, factors in by_severity.items():
        base = _SEVERITY_PENALTY.get(sev, 1.0)
        decay = _SEVERITY_DECAY.get(sev, 0.5)
        factors.sort(reverse=True)  # the full-rate hit goes to the strongest evidence
        for rank, confidence in enumerate(factors):
            total += base * confidence * (decay**rank)
    return total


def _category_explanation(
    category: str,
    members: list[dict[str, Any]],
    counts: dict[str, int],
    penalty: float,
    score: int,
) -> str:
    if not members:
        return f"No {category} findings; category at full score."
    parts = ", ".join(f"{n} {sev}" for sev, n in counts.items())
    return f"{len(members)} finding(s) ({parts}) → −{round(penalty)} points → {score}/100."


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result
