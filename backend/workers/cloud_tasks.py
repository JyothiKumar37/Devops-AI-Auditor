"""Celery tasks for periodic cloud synchronization (Phase 4).

Hourly (configurable) discovery keeps the asset inventory, findings, graph and
drift fresh and detects risk-significant changes. Each task opens its own
Database/session (the worker pattern) and never raises for expected errors.
"""

from __future__ import annotations

import asyncio
import uuid

from core.logging import get_logger
from workers.celery_app import celery_app

logger = get_logger(__name__)


@celery_app.task(name="workers.run_cloud_sync")
def run_cloud_sync(account_id: str) -> None:
    """Synchronize a single cloud account."""

    async def _run() -> None:
        from core.config import get_settings
        from core.database import Database
        from services.cloud_discovery_service import CloudDiscoveryService

        settings = get_settings()
        database = Database(settings)
        try:
            async with database.sessionmaker() as session:
                await CloudDiscoveryService(session, settings).sync(uuid.UUID(account_id))
                await session.commit()
        finally:
            await database.dispose()
        # Phase 5: feed the fresh cloud findings/changes into security ingestion.
        if settings.security_ops_enabled:
            from workers.security_tasks import run_security_ingest_cloud

            run_security_ingest_cloud.delay(account_id)

    try:
        asyncio.run(_run())
    except Exception:  # noqa: BLE001 - the sync records failure; log and move on
        logger.exception("run_cloud_sync_failed", account_id=account_id)


@celery_app.task(name="workers.sync_all_cloud_accounts")
def sync_all_cloud_accounts() -> None:
    """Fan out a sync for every connected cloud account (beat entrypoint)."""

    async def _ids() -> list[str]:
        from sqlalchemy import select

        from core.config import get_settings
        from core.database import Database
        from models.cloud import CloudAccount

        settings = get_settings()
        database = Database(settings)
        try:
            async with database.sessionmaker() as session:
                rows = await session.scalars(select(CloudAccount.id))
                return [str(r) for r in rows.all()]
        finally:
            await database.dispose()

    try:
        for account_id in asyncio.run(_ids()):
            run_cloud_sync.delay(account_id)
    except Exception:  # noqa: BLE001
        logger.exception("sync_all_cloud_accounts_failed")
