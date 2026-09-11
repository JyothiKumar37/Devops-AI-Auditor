"""Typed state passed between nodes of the audit graph."""

from __future__ import annotations

from typing import TypedDict

from scanners.base import Finding


class AuditState(TypedDict, total=False):
    """State threaded through the audit orchestration graph.

    Attributes:
        job_id: Identifier of the scan job being processed.
        repository_root: Local path to the checked-out repository.
        discovered_files: Files discovered during planning, grouped later by type.
        findings: Accumulated findings produced by scanners.
        completed: Whether the pipeline has finished.
    """

    job_id: str
    repository_root: str
    discovered_files: list[str]
    findings: list[Finding]
    completed: bool
