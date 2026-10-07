"""AI security review agent (Phase 3, optional, non-authoritative).

A targeted "second opinion" over a completed scan: it looks for security design
and interaction risks the deterministic rules may miss - authentication/
authorization gaps, insecure configuration interactions, secret-exposure
patterns, unsafe trust boundaries, supply-chain and CI/CD risks.

It is grounded in the scan's deterministic findings and a bounded, DevOps-
relevant subset of repository files (never the whole repo in one prompt). Output
is ``source=AI_REVIEW`` / ``authoritative=False`` - it never changes a
deterministic finding, severity, score, policy result, or gate. Best-effort:
any failure yields no items.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.investigation.review_agent import run_review
from agents.investigation.schemas import AIReviewItem
from agents.investigation.tools._common import load_findings_with_paths
from agents.reasoning.llm import LLMProvider, get_provider
from core.config import Settings
from core.exceptions import NotFoundError
from core.logging import get_logger
from models.scan import RepositoryFile, Scan
from services.runtime_config import resolve_settings

logger = get_logger(__name__)

_MAX_CANDIDATE_FILES = 40

_ROLE = "the AI security review agent"
_INSTRUCTIONS = (
    "You perform a targeted security review of a scanned repository. Look for "
    "risks that line-level rules miss: authentication/authorization gaps, "
    "insecure configuration interactions across files, secret-exposure patterns, "
    "unsafe trust boundaries, supply-chain risks, and CI/CD security weaknesses."
)


def _v(x: Any) -> str:
    return x.value if hasattr(x, "value") else str(x)


class AiSecurityReviewService:
    """Runs a bounded, grounded AI security review over a scan (advisory only)."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    async def review_scan(self, scan_id: uuid.UUID) -> dict[str, Any]:
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")
        items = await self._review(scan_id, scan.repository_name)
        return {
            "scan_id": str(scan_id),
            "label": "AI Security Review",
            "authoritative": False,
            "ai_used": self._provider().available,
            "note": (
                "AI security review is advisory and non-authoritative; it never "
                "changes deterministic findings, scores, policy, or gates."
            ),
            "items": [i.to_dict() for i in items],
        }

    async def _review(self, scan_id: uuid.UUID, repo: str) -> list[AIReviewItem]:
        try:
            items_with_paths = await load_findings_with_paths(self._session, scan_id)
            findings = [
                {
                    "rule_id": f.rule_id,
                    "scanner": f.scanner,
                    "severity": _v(f.severity),
                    "category": _v(f.category),
                    "title": f.title,
                    "file": path,
                }
                for f, path in items_with_paths
            ]
            candidate_files = await self._candidate_files(scan_id, findings)
            if not candidate_files:
                return []
            resolved = await resolve_settings(self._session, self._settings)
            provider = get_provider(resolved)
            return await run_review(
                provider,
                role=_ROLE,
                instructions=_INSTRUCTIONS,
                repo_name=repo,
                findings=findings,
                candidate_files=candidate_files,
                max_items=self._settings.ai_review_max_items,
            )
        except Exception as exc:  # noqa: BLE001 - advisory; never raise into the scan
            logger.warning("ai_security_review_failed", scan=str(scan_id), error=str(exc))
            return []

    async def _candidate_files(
        self, scan_id: uuid.UUID, findings: list[dict[str, Any]]
    ) -> set[str]:
        # Files referenced by findings, plus a bounded set of DevOps-relevant files
        # so the model can reason about cross-file configuration interactions.
        files: set[str] = {f["file"] for f in findings if f.get("file")}
        rows = await self._session.scalars(
            select(RepositoryFile.path)
            .where(RepositoryFile.scan_id == scan_id, RepositoryFile.file_type != "other")
            .limit(_MAX_CANDIDATE_FILES)
        )
        files.update(rows.all())
        return set(list(files)[:_MAX_CANDIDATE_FILES])

    def _provider(self) -> LLMProvider:
        return get_provider(self._settings)
