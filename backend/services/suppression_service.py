"""Finding suppression (baseline) service.

Suppressions let a user baseline a finding - false positive, accepted risk, or
won't-fix - with a reason. They are scoped to a repository and keyed by a stable
fingerprint, so the decision automatically carries across future scans of the
same repository (a re-scan of the repo re-uses the same baseline without any
re-suppression).
"""

from __future__ import annotations

import uuid

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.exceptions import NotFoundError
from core.logging import get_logger
from models.enums import SuppressionReason
from models.finding import Finding
from models.scan import RepositoryFile, Scan
from models.suppression import Suppression
from services.fingerprint import finding_fingerprint

logger = get_logger(__name__)


async def suppressed_fingerprints(
    session: AsyncSession, repository_name: str
) -> set[str]:
    """Return the set of suppressed finding fingerprints for a repository.

    Shared by the readiness/reporting paths so suppressed (baselined) findings do
    not count against a repository's production-readiness assessment.
    """
    rows = await session.scalars(
        select(Suppression.fingerprint).where(
            Suppression.repository_name == repository_name
        )
    )
    return set(rows.all())


class SuppressionService:
    """Manages finding suppressions (baselines) scoped per repository."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _finding_context(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID
    ) -> tuple[Scan, Finding, str]:
        """Load the finding (validating scan ownership) with its repo + file path."""
        finding = await self._session.get(Finding, finding_id)
        if finding is None or finding.scan_id != scan_id:
            raise NotFoundError(f"Finding {finding_id} not found for scan {scan_id}.")
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")
        path = ""
        if finding.file_id is not None:
            repo_file = await self._session.get(RepositoryFile, finding.file_id)
            if repo_file is not None:
                path = repo_file.path
        return scan, finding, path

    async def suppress(
        self,
        scan_id: uuid.UUID,
        finding_id: uuid.UUID,
        reason: SuppressionReason,
        note: str = "",
    ) -> Suppression:
        """Baseline a finding for its repository (create or update the entry)."""
        scan, finding, path = await self._finding_context(scan_id, finding_id)
        fingerprint = finding_fingerprint(finding.rule_id, path, finding.evidence)

        existing = await self._session.scalar(
            select(Suppression).where(
                Suppression.repository_name == scan.repository_name,
                Suppression.fingerprint == fingerprint,
            )
        )
        if existing is not None:
            existing.reason = reason
            existing.note = note
            suppression = existing
        else:
            suppression = Suppression(
                id=uuid.uuid4(),
                repository_name=scan.repository_name,
                fingerprint=fingerprint,
                rule_id=finding.rule_id,
                file_path=path or None,
                reason=reason,
                note=note,
            )
            self._session.add(suppression)
        await self._session.commit()
        logger.info(
            "finding_suppressed",
            repository=scan.repository_name,
            rule_id=finding.rule_id,
            reason=reason.value,
        )
        return suppression

    async def unsuppress(self, scan_id: uuid.UUID, finding_id: uuid.UUID) -> bool:
        """Remove a finding's baseline for its repository. Idempotent."""
        scan, finding, path = await self._finding_context(scan_id, finding_id)
        fingerprint = finding_fingerprint(finding.rule_id, path, finding.evidence)
        result = await self._session.execute(
            delete(Suppression).where(
                Suppression.repository_name == scan.repository_name,
                Suppression.fingerprint == fingerprint,
            )
        )
        await self._session.commit()
        removed = bool(result.rowcount)
        if removed:
            logger.info(
                "finding_unsuppressed",
                repository=scan.repository_name,
                rule_id=finding.rule_id,
            )
        return removed

    async def list_for_scan(self, scan_id: uuid.UUID) -> tuple[Scan, list[Suppression]]:
        """List suppressions in effect for the scan's repository."""
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")
        items = list(
            (
                await self._session.scalars(
                    select(Suppression)
                    .where(Suppression.repository_name == scan.repository_name)
                    .order_by(Suppression.created_at.desc())
                )
            ).all()
        )
        return scan, items

    async def map_for_repository(self, repository_name: str) -> dict[str, Suppression]:
        """Return the repository's suppressions keyed by fingerprint."""
        rows = (
            await self._session.scalars(
                select(Suppression).where(
                    Suppression.repository_name == repository_name
                )
            )
        ).all()
        return {row.fingerprint: row for row in rows}
