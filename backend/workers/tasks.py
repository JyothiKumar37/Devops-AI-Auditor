"""Celery task definitions.

Scans can be long-running (large repositories, network clones), so when async
execution is enabled the API creates a PENDING scan and enqueues one of these
tasks; the worker then runs the full pipeline off the request path.

Each task drives the async `ScanService` pipeline via ``asyncio.run`` in the
worker process (no event loop is running there) using its own database session,
and always leaves the scan in a terminal state (COMPLETED or FAILED) - the
pipeline records failures itself, so tasks never raise for expected errors.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable

from core.config import get_settings
from core.database import Database
from core.logging import get_logger
from services.scan_service import ScanService
from workers.celery_app import celery_app

logger = get_logger(__name__)


@celery_app.task(name="workers.ping")
def ping() -> str:
    """Trivial task used to verify the worker and broker are wired correctly."""
    logger.info("worker_ping")
    return "pong"


async def _with_service(run: Callable[[ScanService], Awaitable[object]]) -> None:
    """Run a pipeline coroutine with a fresh service + database session."""
    settings = get_settings()
    database = Database(settings)
    try:
        async with database.sessionmaker() as session:
            service = ScanService(session=session, settings=settings)
            await run(service)
    finally:
        await database.dispose()


@celery_app.task(name="workers.run_zip_scan")
def run_zip_scan(scan_id: str) -> None:
    """Extract and scan a previously-uploaded ZIP scan."""
    sid = uuid.UUID(scan_id)
    try:
        asyncio.run(_with_service(lambda svc: svc.run_zip_pipeline(sid)))
    except Exception:  # noqa: BLE001 - the pipeline records FAILED; log and move on
        logger.exception("run_zip_scan_failed", scan_id=scan_id)


@celery_app.task(name="workers.run_git_scan")
def run_git_scan(scan_id: str, repository_url: str, ref: str | None = None) -> None:
    """Clone and scan a previously-created git scan."""
    sid = uuid.UUID(scan_id)
    try:
        asyncio.run(
            _with_service(lambda svc: svc.run_git_pipeline(sid, repository_url, ref))
        )
    except Exception:  # noqa: BLE001 - the pipeline records FAILED; log and move on
        logger.exception("run_git_scan_failed", scan_id=scan_id)


@celery_app.task(name="workers.run_pr_scan")
def run_pr_scan(
    provider: str, integration_id: str, repo_full_name: str, pr_number: int
) -> None:
    """Run an incremental scan + PR feedback for a webhook-triggered PR."""

    async def _run() -> None:
        from core.config import get_settings
        from core.database import Database
        from services.pr_feedback_service import PRFeedbackService

        settings = get_settings()
        database = Database(settings)
        try:
            async with database.sessionmaker() as session:
                feedback = PRFeedbackService(session=session, settings=settings)
                await feedback.scan_and_report(
                    provider, uuid.UUID(integration_id), repo_full_name, pr_number
                )
                await session.commit()
        finally:
            await database.dispose()

    try:
        asyncio.run(_run())
    except Exception:  # noqa: BLE001 - log and move on; the webhook already returned 202
        logger.exception(
            "run_pr_scan_failed", repo=repo_full_name, pr=pr_number, provider=provider
        )
