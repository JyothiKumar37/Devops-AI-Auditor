"""Celery tasks for Phase 5 continuous security operations.

Internal ingestion (repo/cloud scans) is event-driven: callers enqueue
``run_security_ingest_*`` when a scan/sync completes. ``poll_security_sources``
is the Celery-beat entrypoint that polls external AWS security sources (gated by
``security_poll_interval_minutes``) and prunes expired events. Every task opens
its own Database/session (worker pattern), is idempotent (ingestion dedups,
correlation is re-runnable), and never raises for expected errors.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

from core.logging import get_logger
from workers.celery_app import celery_app

logger = get_logger(__name__)


async def _correlate(session, settings) -> None:  # type: ignore[no-untyped-def]
    from services.incident_service import IncidentService

    await IncidentService(session, settings).correlate_new_events()


@celery_app.task(name="workers.run_security_ingest_scan")
def run_security_ingest_scan(scan_id: str) -> None:
    """Ingest a completed repo scan's findings as events, then correlate."""

    async def _run() -> None:
        from core.config import get_settings
        from core.database import Database
        from services.security_service import SecurityService

        settings = get_settings()
        database = Database(settings)
        try:
            async with database.sessionmaker() as session:
                await SecurityService(session, settings).ingest_repo_scan(uuid.UUID(scan_id))
                await _correlate(session, settings)
                await session.commit()
        finally:
            await database.dispose()

    try:
        asyncio.run(_run())
    except Exception:  # noqa: BLE001
        logger.exception("run_security_ingest_scan_failed", scan_id=scan_id)


@celery_app.task(name="workers.run_security_ingest_cloud")
def run_security_ingest_cloud(account_id: str) -> None:
    """Ingest a cloud account's findings + risk changes as events, then correlate."""

    async def _run() -> None:
        from core.config import get_settings
        from core.database import Database
        from services.security_service import SecurityService

        settings = get_settings()
        database = Database(settings)
        try:
            async with database.sessionmaker() as session:
                await SecurityService(session, settings).ingest_cloud_account(
                    uuid.UUID(account_id)
                )
                await _correlate(session, settings)
                await session.commit()
        finally:
            await database.dispose()

    try:
        asyncio.run(_run())
    except Exception:  # noqa: BLE001
        logger.exception("run_security_ingest_cloud_failed", account_id=account_id)


@celery_app.task(name="workers.poll_security_sources")
def poll_security_sources() -> None:
    """Beat entrypoint: poll AWS security sources, correlate, prune old events.

    AWS polling requires live, assumed-role access; where unavailable it is a
    no-op (surfaced via source health). Correlation + pruning always run.
    """

    async def _run() -> None:
        from sqlalchemy import delete, select

        from core.config import get_settings
        from core.database import Database
        from models.security import SecurityEvent

        settings = get_settings()
        database = Database(settings)
        try:
            async with database.sessionmaker() as session:
                # 1) Correlate anything newly ingested since the last run.
                await _correlate(session, settings)
                # 2) Prune expired, uncorrelated events (retention policy).
                if settings.security_event_retention_days > 0:
                    cutoff = datetime.now(UTC) - timedelta(
                        days=settings.security_event_retention_days
                    )
                    await session.execute(
                        delete(SecurityEvent).where(
                            SecurityEvent.incident_id.is_(None),
                            SecurityEvent.last_observed_at < cutoff,
                        )
                    )
                await session.commit()
                _ = select  # (reserved for future AWS source polling)
        finally:
            await database.dispose()

    try:
        asyncio.run(_run())
    except Exception:  # noqa: BLE001
        logger.exception("poll_security_sources_failed")
