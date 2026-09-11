"""Reasoning service.

Loads a scan's deterministic results from the database, builds the reasoning
state, runs the LangGraph workflow (LLM-backed when configured, deterministic
otherwise) and returns the structured audit report.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.reasoning.graph import build_reasoning_graph
from agents.reasoning.llm import get_provider
from core.config import Settings
from core.exceptions import NotFoundError
from core.logging import get_logger
from models.finding import Finding
from models.scan import RepositoryFile, Scan

logger = get_logger(__name__)

# Cross-resource relationship findings that feed the correlation agent.
_RELATIONSHIP_RULES = {
    "K8S026", "K8S027", "K8S070", "K8S071", "K8S072", "K8S073", "K8S074", "K8S075", "K8S076",
    "TF021", "TF025",
}


class ReasoningService:
    """Runs the AI reasoning layer over a completed scan."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    async def generate_report(self, scan_id: uuid.UUID) -> dict[str, Any]:
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")

        path_by_id = {
            rf.id: rf.path
            for rf in (
                await self._session.scalars(
                    select(RepositoryFile).where(RepositoryFile.scan_id == scan_id)
                )
            ).all()
        }
        files = [
            {"path": rf_path, "file_type": rf_type, "size": rf_size}
            for rf_path, rf_type, rf_size in (
                await self._session.execute(
                    select(RepositoryFile.path, RepositoryFile.file_type, RepositoryFile.size)
                    .where(RepositoryFile.scan_id == scan_id)
                )
            ).all()
        ]

        findings_rows = (
            await self._session.scalars(select(Finding).where(Finding.scan_id == scan_id))
        ).all()
        findings = [self._normalize(f, path_by_id) for f in findings_rows]
        relationships = [f for f in findings if f["rule_id"] in _RELATIONSHIP_RULES]

        provider = get_provider(self._settings)
        graph = build_reasoning_graph(provider)
        initial: dict[str, Any] = {
            "scan_id": str(scan_id),
            "files": files,
            "findings": findings,
            "relationships": relationships,
            "correlation_index": scan.correlation_index or {},
            "domain_findings": [],
            "llm_used": provider.available,
        }
        logger.info("reasoning_started", scan_id=str(scan_id), provider=provider.name,
                    findings=len(findings))
        result = graph.invoke(initial)
        return result["report"]

    @staticmethod
    def _normalize(finding: Finding, path_by_id: dict[uuid.UUID, str]) -> dict[str, Any]:
        return {
            "id": str(finding.id),
            "scanner": str(finding.scanner),
            "rule_id": str(finding.rule_id),
            "category": str(finding.category),
            "severity": str(finding.severity),
            "confidence": str(finding.confidence),
            "title": finding.title,
            "description": finding.description or "",
            "evidence": finding.evidence,
            "file": path_by_id.get(finding.file_id) if finding.file_id else None,
            "line": finding.line_number,
            "recommendation": finding.recommendation or "",
        }
