"""AI-assisted PR review (Phase 3, non-authoritative).

Runs AFTER the deterministic Phase 2 PR scan + policy. It looks for architectural,
configuration-interaction, deployment and reliability risks the deterministic
rules may miss, grounded in the PR's new findings and changed files. Results are
labeled ``source=AI_REVIEW`` / ``authoritative=False`` and NEVER change the PR
gate, policy outcome, or CI result. Best-effort: any failure yields no items.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from agents.investigation.review_agent import run_review
from agents.investigation.schemas import AIReviewItem
from agents.reasoning.llm import LLMProvider, get_provider
from core.config import Settings
from core.exceptions import NotFoundError
from core.logging import get_logger
from models.pullrequest import PullRequest, PullRequestScan
from services.runtime_config import resolve_settings

logger = get_logger(__name__)

_ROLE = "the AI pull-request reviewer"
_INSTRUCTIONS = (
    "You review a pull request's incremental scan. Focus on risks that span "
    "configuration interactions, deployment/rollout implications, scaling and "
    "reliability concerns, and architectural issues - things a line-level rule "
    "would not catch."
)


class AiPrReviewService:
    """Produces best-effort, non-authoritative AI review notes for a PR scan."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    async def review_pull_request(self, pr_id: uuid.UUID) -> dict[str, Any]:
        """Review the latest scan of a pull request."""
        from sqlalchemy import select

        pr = await self._session.get(PullRequest, pr_id)
        if pr is None:
            raise NotFoundError(f"Pull request {pr_id} not found.")
        latest = await self._session.scalar(
            select(PullRequestScan)
            .where(PullRequestScan.pull_request_id == pr_id)
            .order_by(PullRequestScan.created_at.desc())
            .limit(1)
        )
        if latest is None:
            raise NotFoundError(f"Pull request {pr_id} has no scans yet.")
        return await self.review_pr_scan(latest.id)

    async def review_pr_scan(self, pr_scan_id: uuid.UUID) -> dict[str, Any]:
        pr_scan = await self._session.get(PullRequestScan, pr_scan_id)
        if pr_scan is None:
            raise NotFoundError(f"PR scan {pr_scan_id} not found.")
        pr = await self._session.get(PullRequest, pr_scan.pull_request_id)
        repo = pr.repo_full_name if pr else ""
        items = await self._review(repo, pr_scan)
        return {
            "pr_scan_id": str(pr_scan_id),
            "label": "AI Review",
            "authoritative": False,
            "ai_used": bool(items) or self._provider().available,
            "note": (
                "AI review is advisory and never changes the deterministic gate, "
                "policy result, or CI outcome."
            ),
            "items": [i.to_dict() for i in items],
        }

    async def _review(self, repo: str, pr_scan: PullRequestScan) -> list[AIReviewItem]:
        findings = list(pr_scan.findings_detail or [])
        candidate_files = _files_from_findings(findings)
        if not candidate_files:
            return []
        try:
            provider = self._provider()
            return await run_review(
                provider,
                role=_ROLE,
                instructions=_INSTRUCTIONS,
                repo_name=repo,
                findings=findings,
                candidate_files=candidate_files,
                max_items=self._settings.ai_review_max_items,
            )
        except Exception as exc:  # noqa: BLE001 - advisory; never break the PR flow
            logger.warning("ai_pr_review_failed", error=str(exc))
            return []

    def _provider(self) -> LLMProvider:
        return get_provider(self._settings)


def _files_from_findings(findings: list[dict[str, Any]]) -> set[str]:
    files: set[str] = set()
    for f in findings:
        for key in ("file", "path"):
            value = f.get(key)
            if isinstance(value, str) and value:
                files.add(value)
    return files


async def review_pr_scan_items(
    session: AsyncSession, settings: Settings, pr_scan: PullRequestScan, repo: str
) -> list[AIReviewItem]:
    """Convenience used by the PR feedback hook (resolves runtime model override)."""
    resolved = await resolve_settings(session, settings)
    service = AiPrReviewService(session, resolved)
    return await service._review(repo, pr_scan)  # noqa: SLF001 - internal reuse
