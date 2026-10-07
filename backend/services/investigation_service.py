"""Service layer for AI investigations (Phase 3).

Wraps the agentic :class:`InvestigationEngine` with three scoped entrypoints:
scan-level, finding-level, and repository-level. Each builds a READ-only engine
authorized to exactly the scans in scope, so a natural-language question is
answered by controlled tool calls - never by raw SQL or unrestricted access.

Investigations are stateless here (a result is computed and returned). Persisted
investigation sessions are added in a later milestone.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.investigation.engine import InvestigationEngine
from agents.investigation.schemas import InvestigationResult
from agents.reasoning.sanitize import neutralize
from core.config import Settings
from core.exceptions import NotFoundError, ValidationError
from models.ai_investigation import AIInvestigation
from models.finding import Finding
from models.scan import Scan

_MAX_QUESTION_CHARS = 1000


class InvestigationService:
    """Scoped entrypoints for running AI investigations over scan data."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    async def investigate_scan(self, scan_id: uuid.UUID, question: str) -> InvestigationResult:
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")
        engine = await InvestigationEngine.build(
            self._session, self._settings, scan_id=scan_id,
            repository_name=scan.repository_name,
        )
        result = await engine.investigate(self._clean_question(question))
        await self._persist(result, scope="scan", scan_id=scan_id,
                            repository_name=scan.repository_name)
        return result

    async def investigate_finding(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID, question: str
    ) -> InvestigationResult:
        finding = await self._session.get(Finding, finding_id)
        if finding is None or finding.scan_id != scan_id:
            raise NotFoundError(f"Finding {finding_id} not found for scan {scan_id}.")
        scan = await self._session.get(Scan, scan_id)
        repo = scan.repository_name if scan else None
        # Prefix the finding context so the agent knows what "this finding" means,
        # then let it fetch the full detail via the get_finding tool.
        sev = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
        prefix = (
            f"Investigate finding {finding_id} "
            f"(rule {finding.rule_id}, severity {sev}, scanner {finding.scanner}) "
            f"in scan {scan_id}. "
        )
        engine = await InvestigationEngine.build(
            self._session, self._settings, scan_id=scan_id, repository_name=repo,
        )
        result = await engine.investigate(prefix + self._clean_question(question))
        await self._persist(result, scope="finding", scan_id=scan_id,
                            finding_id=finding_id, repository_name=repo or "")
        return result

    async def investigate_repository(
        self, repository_name: str, question: str
    ) -> InvestigationResult:
        scan_ids = (
            await self._session.scalars(
                select(Scan.id).where(Scan.repository_name == repository_name)
            )
        ).all()
        if not scan_ids:
            raise NotFoundError(f"No scans found for repository '{repository_name}'.")
        # Authorize every scan in the repo so cross-scan/historical tools work,
        # but still confine the agent to this repository's data.
        engine = await InvestigationEngine.build(
            self._session, self._settings, repository_name=repository_name,
        )
        engine._ctx.authorized_scan_ids = frozenset(scan_ids)  # noqa: SLF001 - scope widen
        result = await engine.investigate(self._clean_question(question))
        await self._persist(result, scope="repository", repository_name=repository_name)
        return result

    # ---- persistence / history --------------------------------------------

    async def _persist(
        self,
        result: InvestigationResult,
        *,
        scope: str,
        scan_id: uuid.UUID | None = None,
        finding_id: uuid.UUID | None = None,
        repository_name: str = "",
    ) -> None:
        row = AIInvestigation(
            id=uuid.uuid4(),
            scope=scope,
            scan_id=scan_id,
            finding_id=finding_id,
            repository_name=repository_name,
            question=result.question,
            answer=result.answer,
            root_cause=result.root_cause,
            impact=result.impact,
            confidence=result.confidence,
            label=result.label,
            recommendations=result.recommendations,
            citations=result.citations,
            evidence=result.evidence,
            trace=result.trace,
            ai_used=result.ai_used,
            tool_calls=result.tool_calls,
            hallucination_guard_triggered=result.hallucination_guard_triggered,
        )
        self._session.add(row)
        await self._session.flush()
        result.investigation_id = str(row.id)

    async def list_investigations(
        self,
        *,
        scan_id: uuid.UUID | None = None,
        repository: str | None = None,
        limit: int = 50,
    ) -> Sequence[AIInvestigation]:
        from sqlalchemy import select

        query = select(AIInvestigation).order_by(AIInvestigation.created_at.desc())
        if scan_id is not None:
            query = query.where(AIInvestigation.scan_id == scan_id)
        if repository:
            query = query.where(AIInvestigation.repository_name == repository)
        query = query.limit(min(max(limit, 1), 200))
        return (await self._session.scalars(query)).all()

    async def get_investigation(self, investigation_id: uuid.UUID) -> AIInvestigation:
        row = await self._session.get(AIInvestigation, investigation_id)
        if row is None:
            raise NotFoundError(f"Investigation {investigation_id} not found.")
        return row

    @staticmethod
    def _clean_question(question: str) -> str:
        q = (question or "").strip()
        if not q:
            raise ValidationError("A question is required.")
        return neutralize(q, max_length=_MAX_QUESTION_CHARS)
