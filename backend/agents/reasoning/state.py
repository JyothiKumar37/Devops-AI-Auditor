"""State threaded through the reasoning graph.

Inputs (files, findings, relationships) are captured as plain dicts so the state
is serialisable and each node stays a pure function of it. Agent outputs are
accumulated as their own keys.
"""

from __future__ import annotations

from typing import Any, TypedDict


class ReasoningState(TypedDict, total=False):
    # ---- inputs (from deterministic stages) ----
    scan_id: str
    files: list[dict[str, Any]]          # {path, file_type, size}
    findings: list[dict[str, Any]]       # normalized deterministic findings
    relationships: list[dict[str, Any]]  # subset of cross-resource findings
    correlation_index: dict[str, Any]    # cross-stack entity index

    # ---- agent outputs ----
    understanding: dict[str, Any]
    domain_findings: list[dict[str, Any]]   # AIFinding dicts (all specialists)
    correlations: list[dict[str, Any]]
    finding_groups: list[dict[str, Any]]    # FindingGroup dicts (root-cause groups)
    false_positives: list[dict[str, Any]]   # FalsePositiveAssessment dicts
    prioritized: list[dict[str, Any]]       # AIFinding dicts, sorted, FPs removed
    readiness: dict[str, Any]
    report: dict[str, Any]

    # ---- meta ----
    llm_used: bool
