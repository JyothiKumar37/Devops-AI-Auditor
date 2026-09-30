"""Deterministic container-security scoring (Docker + Compose).

Projects the Docker (``DCKnnn``) and Compose (``DCMPnnn``) findings onto four
container-security dimensions and scores each 0-100, plus a weighted overall
score. Reuses the shared severity/confidence penalty model
(``agents.reasoning.readiness.category_penalty``). No LLM is involved.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from agents.reasoning.readiness import category_penalty

# The four container-security dimensions (key, label, importance weight).
CONTAINER_CATEGORIES: list[tuple[str, str, float]] = [
    ("security", "Security", 0.35),
    ("runtime_hardening", "Runtime Hardening", 0.23),
    ("image_hygiene", "Image Hygiene", 0.22),
    ("build_quality", "Build Quality", 0.20),
]
_WEIGHT = {key: weight for key, _, weight in CONTAINER_CATEGORIES}

# Explicit rule -> dimension mapping (default is "security").
_RULE_CATEGORY: dict[str, str] = {
    # --- Docker (Dockerfile) ---
    "DCK001": "image_hygiene", "DCK002": "image_hygiene", "DCK013": "image_hygiene",
    "DCK003": "runtime_hardening", "DCK004": "runtime_hardening", "DCK012": "runtime_hardening",
    "DCK007": "build_quality", "DCK008": "build_quality", "DCK009": "build_quality",
    "DCK010": "build_quality", "DCK015": "build_quality",
    # DCK005 secrets, DCK006 ports, DCK011 ADD, DCK014 dangerous cmd -> security
    # --- Compose ---
    "DCMP015": "image_hygiene", "DCMP016": "image_hygiene",
    "DCMP006": "runtime_hardening", "DCMP007": "runtime_hardening",
    "DCMP008": "runtime_hardening", "DCMP009": "runtime_hardening",
    "DCMP010": "runtime_hardening",
    "DCMP021": "build_quality", "DCMP022": "build_quality", "DCMP023": "build_quality",
    "DCMP025": "build_quality",
    # DCMP001-005 (privileged/host-ns/caps), DCMP011/012 (secrets),
    # DCMP013/014 (exposed ports), DCMP017-019 (mounts), DCMP024 (insecure) -> security
}


def category_for_rule(rule_id: str) -> str:
    return _RULE_CATEGORY.get(rule_id, "security")


@dataclass(frozen=True, slots=True)
class ContainerCategoryScore:
    key: str
    label: str
    score: int
    findings: int
    counts: dict[str, int] = field(default_factory=dict)
    explanation: str = ""


@dataclass(frozen=True, slots=True)
class ContainerScore:
    applicable: bool
    overall: int
    total_findings: int
    categories: list[ContainerCategoryScore] = field(default_factory=list)


def assess_container(findings: list[dict[str, Any]], *, has_containers: bool) -> ContainerScore:
    """Score container security from ``docker-rules``/``compose-rules`` findings.

    ``findings`` should already be limited to container findings. When the
    repository has no Dockerfile/Compose file the score is not-applicable
    (overall 100).
    """
    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        by_category[category_for_rule(str(finding.get("rule_id", "")))].append(finding)

    categories: list[ContainerCategoryScore] = []
    weighted_sum = 0.0
    weight_total = 0.0
    for key, label, weight in CONTAINER_CATEGORIES:
        members = by_category.get(key, [])
        counts: dict[str, int] = defaultdict(int)
        for f in members:
            counts[str(f.get("severity", "info"))] += 1
        penalty = category_penalty(members)
        score = max(0, min(100, round(100 - penalty)))
        categories.append(
            ContainerCategoryScore(
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
    if not has_containers:
        return ContainerScore(
            applicable=False, overall=100, total_findings=0, categories=categories
        )
    return ContainerScore(
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
