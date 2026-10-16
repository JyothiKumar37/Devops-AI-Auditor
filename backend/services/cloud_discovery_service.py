"""Cloud synchronization: discover AWS resources and persist the asset inventory.

A sync assumes the account's read-only role, discovers resources across the
configured regions (off the event loop, in a thread), then upserts the asset
inventory and records a snapshot. Discovery is metadata-only. Cloud security
rules (findings) and the exposure graph are layered on in later milestones.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.logging import get_logger
from models.cloud import CloudAccount, CloudAsset, CloudSnapshot
from services.audit_service import AuditService
from services.aws import discovery as discovery_mod
from services.aws.client import AWSClientFactory
from services.aws.resources import DiscoveredResource
from services.cloud_account_service import build_factory

logger = get_logger(__name__)

# Rebindable in tests to avoid real AWS calls.
discover_all = discovery_mod.discover_all


class CloudDiscoveryService:
    """Runs discovery for an account and maintains its asset inventory."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings
        self._audit = AuditService(session)

    async def sync(self, account_pk: uuid.UUID) -> CloudSnapshot:
        account = await self._session.get(CloudAccount, account_pk)
        if account is None:
            from core.exceptions import NotFoundError

            raise NotFoundError(f"Cloud account {account_pk} not found.")

        snapshot = CloudSnapshot(
            id=uuid.uuid4(), account_id=account.id, status="running",
            regions=list(account.regions or []),
        )
        self._session.add(snapshot)
        await self._session.flush()
        await self._audit.record(
            "cloud.sync.started", resource_type="cloud_account",
            resource_id=str(account.id), detail={"account_id": account.account_id},
        )

        try:
            resources = await self._discover(account)
        except Exception as exc:  # noqa: BLE001 - record failure, never crash the worker
            snapshot.status = "failed"
            snapshot.error = str(exc)[:1000]
            snapshot.completed_at = datetime.now(UTC)
            account.status = "error"
            account.status_detail = str(exc)[:500]
            await self._session.flush()
            await self._audit.record(
                "cloud.sync.failed", resource_type="cloud_account",
                resource_id=str(account.id), status="failure",
                detail={"account_id": account.account_id, "error": str(exc)[:200]},
            )
            logger.warning("cloud_sync_failed", account_id=account.account_id, error=str(exc))
            return snapshot

        prior = await self._snapshot_prior_state(account.id)
        count = await self._upsert_assets(account, resources)
        finding_count = await self._persist_findings(account, resources, snapshot.id)
        await self._rebuild_graph(account.id)
        await self._detect_changes(account, prior, resources, snapshot.id)
        snapshot.status = "completed"
        snapshot.asset_count = count
        snapshot.finding_count = finding_count
        snapshot.completed_at = datetime.now(UTC)
        account.last_synced_at = datetime.now(UTC)
        if account.status != "error":
            account.status = "connected"
        await self._session.flush()
        await self._audit.record(
            "cloud.sync.completed", resource_type="cloud_account",
            resource_id=str(account.id),
            detail={"account_id": account.account_id, "assets": count},
        )
        logger.info("cloud_sync_completed", account_id=account.account_id, assets=count)
        return snapshot

    async def list_assets(
        self,
        account_pk: uuid.UUID,
        *,
        service: str | None = None,
        region: str | None = None,
        exposure: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> tuple[list[CloudAsset], int]:
        query = select(CloudAsset).where(CloudAsset.account_id == account_pk)
        if service:
            query = query.where(CloudAsset.service == service)
        if region:
            query = query.where(CloudAsset.region == region)
        if exposure:
            query = query.where(CloudAsset.exposure == exposure)
        rows = list((await self._session.scalars(query)).all())
        total = len(rows)
        rows.sort(key=lambda a: (a.service, a.resource_id))
        page = rows[offset : offset + min(max(limit, 1), 500)]
        return page, total

    async def get_asset(self, asset_pk: uuid.UUID) -> CloudAsset:
        from core.exceptions import NotFoundError

        asset = await self._session.get(CloudAsset, asset_pk)
        if asset is None:
            raise NotFoundError(f"Cloud asset {asset_pk} not found.")
        return asset

    # ---- internals --------------------------------------------------------

    async def _discover(self, account: CloudAccount) -> list[DiscoveredResource]:
        from core.crypto import require_cipher

        external_id = None
        if account.encrypted_external_id:
            external_id = require_cipher(self._settings).decrypt(account.encrypted_external_id)
        factory: AWSClientFactory = build_factory(self._settings)
        regions = list(account.regions or self._settings.aws_default_regions_list)

        def _run() -> list[DiscoveredResource]:
            assumed = factory.assume_role(account.role_arn, external_id)
            return discover_all(assumed, regions)

        return await asyncio.to_thread(_run)

    async def _upsert_assets(
        self, account: CloudAccount, resources: list[DiscoveredResource]
    ) -> int:
        existing = {
            (a.service, a.resource_id): a
            for a in (
                await self._session.scalars(
                    select(CloudAsset).where(CloudAsset.account_id == account.id)
                )
            ).all()
        }
        now = datetime.now(UTC)
        for res in resources:
            key = (res.service, res.resource_id)
            asset = existing.get(key)
            if asset is None:
                asset = CloudAsset(
                    id=uuid.uuid4(), account_id=account.id, service=res.service,
                    resource_type=res.resource_type, resource_id=res.resource_id,
                    arn=res.arn, name=res.name, region=res.region, state=res.state,
                    exposure=res.exposure, tags=res.tags, attributes=res.attributes,
                    first_discovered_at=now, last_synced_at=now,
                )
                self._session.add(asset)
                existing[key] = asset
            else:
                asset.resource_type = res.resource_type
                asset.arn = res.arn
                asset.name = res.name
                asset.region = res.region
                asset.state = res.state
                asset.exposure = res.exposure
                asset.tags = res.tags
                asset.attributes = res.attributes
                asset.last_synced_at = now
        await self._session.flush()
        return len(resources)

    async def _snapshot_prior_state(
        self, account_pk: uuid.UUID
    ) -> dict[tuple[str, str], dict]:
        """Capture the pre-sync asset state (for change detection)."""
        rows = (
            await self._session.scalars(
                select(CloudAsset).where(CloudAsset.account_id == account_pk)
            )
        ).all()
        return {
            (a.service, a.resource_id): {"exposure": a.exposure, "attributes": a.attributes}
            for a in rows
        }

    async def _detect_changes(
        self,
        account: CloudAccount,
        prior: dict[tuple[str, str], dict],
        resources: list[DiscoveredResource],
        snapshot_id: uuid.UUID,
    ) -> None:
        """Record added/removed/modified resources and notify on risky changes."""
        from models.cloud import CloudChange
        from services.aws.changes import detect_changes

        if not prior:
            return  # first sync establishes the baseline; nothing to diff against

        changes = detect_changes(prior, resources)
        risky: list = []
        for ch in changes:
            self._session.add(
                CloudChange(
                    id=uuid.uuid4(), account_id=account.id, snapshot_id=snapshot_id,
                    service=ch.service, resource_id=ch.resource_id,
                    change_type=ch.change_type, detail=ch.detail,
                    risk_significant=ch.risk_significant,
                )
            )
            if ch.risk_significant:
                risky.append(ch)
        await self._session.flush()
        if risky:
            await self._notify_risky_changes(account, risky)

    async def _notify_risky_changes(self, account: CloudAccount, risky: list) -> None:
        """Best-effort notification; a failure never breaks the sync."""
        try:
            from services.notification_service import NotificationService
            from services.notifications import Notification, NotificationEvent

            summary = ", ".join(f"{c.change_type} {c.resource_id}" for c in risky[:5])
            await NotificationService(self._session, self._settings).dispatch(
                NotificationEvent.CLOUD_CHANGE.value,
                Notification(
                    event=NotificationEvent.CLOUD_CHANGE.value,
                    title=f"Risk-significant cloud changes in {account.account_id}",
                    body=f"{len(risky)} security-relevant change(s): {summary}",
                    severity="high",
                    fields={"account_id": account.account_id, "changes": str(len(risky))},
                ),
            )
        except Exception as exc:  # noqa: BLE001 - monitoring must never fail the sync
            logger.warning("cloud_change_notify_failed", error=str(exc))

    async def list_changes(
        self, account_pk: uuid.UUID, *, risk_only: bool = False, limit: int = 100
    ) -> list:
        from models.cloud import CloudChange

        query = (
            select(CloudChange)
            .where(CloudChange.account_id == account_pk)
            .order_by(CloudChange.created_at.desc())
        )
        if risk_only:
            query = query.where(CloudChange.risk_significant.is_(True))
        return list((await self._session.scalars(query.limit(min(max(limit, 1), 500)))).all())

    async def _rebuild_graph(self, account_pk: uuid.UUID) -> None:
        from services.cloud_graph_service import CloudGraphService

        await CloudGraphService(self._session, self._settings).rebuild(account_pk)

    async def _persist_findings(
        self, account: CloudAccount, resources: list[DiscoveredResource], snapshot_id: uuid.UUID
    ) -> int:
        """Re-evaluate all cloud rules and replace this account's cloud findings."""
        from sqlalchemy import delete

        from models.cloud import CloudFinding
        from services.aws.rules import all_rules, evaluate_asset
        from services.aws.rules.base import scanner_for_service
        from services.fingerprint import finding_fingerprint

        await self._session.execute(
            delete(CloudFinding).where(CloudFinding.account_id == account.id)
        )
        rules = all_rules()
        created = 0
        for res in resources:
            for cf in evaluate_asset(res, rules):
                self._session.add(
                    CloudFinding(
                        id=uuid.uuid4(),
                        account_id=account.id,
                        snapshot_id=snapshot_id,
                        service=cf.service,
                        resource_id=cf.resource_id,
                        region=cf.region,
                        rule_id=cf.rule_id,
                        scanner=scanner_for_service(cf.service),
                        category=cf.category.value,
                        severity=cf.severity.value,
                        confidence=cf.confidence.value,
                        title=cf.title,
                        description=cf.description,
                        evidence=cf.evidence,
                        recommendation=cf.recommendation,
                        fingerprint=finding_fingerprint(cf.rule_id, cf.resource_id, cf.evidence),
                        compliance=list(cf.compliance),
                    )
                )
                created += 1
        await self._session.flush()
        return created
