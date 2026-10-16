"""Public façade for Phase 5 security-event ingestion + querying.

Bridges the deterministic Phase 1-4 engines and the external adapters into the
normalized event store, and exposes read queries for the API. Internal sources
(repo/cloud scans, cloud changes) are pulled on demand; external sources (AWS
native, webhooks) are pushed in after authentication.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.crypto import require_cipher
from core.exceptions import NotFoundError, ValidationError
from core.logging import get_logger
from models.cloud import CloudAccount, CloudChange, CloudFinding
from models.enums import SecurityEventSourceType
from models.security import SecurityEvent, SecurityEventSource
from services.security.adapters import aws as aws_adapter
from services.security.adapters import internal as internal_adapter
from services.security.adapters import webhook as webhook_adapter
from services.security.ingest import IngestResult, SecurityIngestService
from services.security.normalize import NormalizedEvent
from services.security.webhook_auth import verify_webhook

logger = get_logger(__name__)

_WEBHOOK_SOURCES = {
    SecurityEventSourceType.CICD.value,
    SecurityEventSourceType.FALCO.value,
    SecurityEventSourceType.ALERTMANAGER.value,
}


def _now() -> datetime:
    return datetime.now(UTC)


class SecurityService:
    """Ingestion + query operations over normalized security events."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings
        self._ingest = SecurityIngestService(session, settings)

    # ---- internal (verified) ingestion -----------------------------------

    async def ingest_repo_scan(self, scan_id: uuid.UUID) -> IngestResult:
        """Normalize + ingest the active findings of a completed repository scan."""
        from agents.investigation.tools._common import load_findings_with_paths
        from models.scan import Scan
        from services.fingerprint import finding_fingerprint
        from services.suppression_service import suppressed_fingerprints

        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")
        suppressed = await suppressed_fingerprints(self._session, scan.repository_name)
        events: list[NormalizedEvent] = []
        for finding, path in await load_findings_with_paths(self._session, scan_id):
            if finding_fingerprint(finding.rule_id, path, finding.evidence) in suppressed:
                continue
            events.append(
                internal_adapter.event_from_repo_finding(finding, path, scan.repository_name)
            )
        return await self._ingest.ingest_many(events)

    async def ingest_cloud_account(self, account_id: uuid.UUID) -> IngestResult:
        """Normalize + ingest a cloud account's findings and risk-significant changes."""
        account = await self._session.get(CloudAccount, account_id)
        if account is None:
            raise NotFoundError(f"Cloud account {account_id} not found.")

        findings = (
            await self._session.scalars(
                select(CloudFinding).where(CloudFinding.account_id == account_id)
            )
        ).all()
        changes = (
            await self._session.scalars(
                select(CloudChange).where(
                    CloudChange.account_id == account_id,
                    CloudChange.risk_significant.is_(True),
                )
            )
        ).all()
        events = [internal_adapter.event_from_cloud_finding(f, account) for f in findings]
        events += [internal_adapter.event_from_cloud_change(c, account) for c in changes]
        return await self._ingest.ingest_many(events)

    # ---- AWS native ingestion (push; raw dicts from poll or fixtures) -----

    async def ingest_aws_findings(
        self,
        source_type: str,
        raw: list[dict[str, Any]],
        *,
        account: CloudAccount | None = None,
    ) -> IngestResult:
        """Normalize + ingest raw AWS findings/events of one source type."""
        account_ref = account.account_id if account else ""
        account_pk = account.id if account else None
        mapper = {
            SecurityEventSourceType.GUARDDUTY.value: aws_adapter.event_from_guardduty,
            SecurityEventSourceType.SECURITY_HUB.value: aws_adapter.event_from_security_hub,
            SecurityEventSourceType.CLOUDTRAIL.value: aws_adapter.event_from_cloudtrail,
            SecurityEventSourceType.CONFIG.value: aws_adapter.event_from_config,
        }.get(source_type)
        if mapper is None:
            raise ValidationError(f"Unsupported AWS source type '{source_type}'.")
        events = [
            mapper(item, account_ref=account_ref, cloud_account_id=account_pk)
            for item in raw
            if isinstance(item, dict)
        ]
        return await self._ingest.ingest_many(events)

    # ---- webhook ingestion (authenticated) --------------------------------

    async def ingest_webhook(
        self, source_type: str, headers: dict[str, str], body: bytes
    ) -> IngestResult:
        """Authenticate + parse + ingest an inbound security webhook."""
        if source_type not in _WEBHOOK_SOURCES:
            raise ValidationError(f"Unsupported webhook source '{source_type}'.")
        if len(body) > self._settings.security_webhook_max_body_bytes:
            raise ValidationError("Webhook payload too large.")

        source = await self._get_source(source_type, None)
        secret = self._source_secret(source) if source else ""
        verify_webhook(
            secret=secret,
            body=body,
            signature=headers.get("x-signature") or headers.get("x-hub-signature-256"),
            timestamp=headers.get("x-timestamp"),
            replay_window_seconds=self._settings.security_webhook_replay_window_seconds,
        )
        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValidationError("Webhook body is not valid JSON.") from exc
        if not isinstance(payload, dict):
            raise ValidationError("Webhook body must be a JSON object.")

        if source_type == SecurityEventSourceType.CICD.value:
            events = webhook_adapter.events_from_cicd(payload)
        elif source_type == SecurityEventSourceType.FALCO.value:
            events = [webhook_adapter.event_from_falco(payload)]
        else:  # alertmanager
            events = webhook_adapter.events_from_alertmanager(payload)
        return await self._ingest.ingest_many(events)

    # ---- source management -------------------------------------------------

    async def register_source(
        self,
        source_type: str,
        *,
        secret: str | None = None,
        cloud_account_id: uuid.UUID | None = None,
        name: str = "",
        config: dict[str, Any] | None = None,
    ) -> SecurityEventSource:
        """Create or update a source (optionally with an encrypted webhook secret)."""
        source = await self._get_source(source_type, cloud_account_id)
        if source is None:
            source = SecurityEventSource(
                id=uuid.uuid4(),
                source_type=source_type,
                name=name or source_type,
                cloud_account_id=cloud_account_id,
                config=config or {},
            )
            self._session.add(source)
        else:
            if name:
                source.name = name
            if config is not None:
                source.config = config
        if secret:
            source.encrypted_secret = require_cipher(self._settings).encrypt(secret)
        await self._session.flush()
        return source

    async def list_sources(self) -> Sequence[SecurityEventSource]:
        return (
            await self._session.scalars(
                select(SecurityEventSource).order_by(SecurityEventSource.source_type)
            )
        ).all()

    # ---- queries -----------------------------------------------------------

    async def list_events(
        self,
        *,
        source_type: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        resource_id: str | None = None,
        cloud_account_id: uuid.UUID | None = None,
        verified: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[Sequence[SecurityEvent], int]:
        query = select(SecurityEvent)
        count_q = select(func.count()).select_from(SecurityEvent)
        conditions = []
        if source_type:
            conditions.append(SecurityEvent.source_type == source_type)
        if severity:
            conditions.append(SecurityEvent.severity == severity)
        if status:
            conditions.append(SecurityEvent.status == status)
        if resource_id:
            conditions.append(SecurityEvent.resource_id == resource_id)
        if cloud_account_id:
            conditions.append(SecurityEvent.cloud_account_id == cloud_account_id)
        if verified is not None:
            conditions.append(SecurityEvent.verified.is_(verified))
        for cond in conditions:
            query = query.where(cond)
            count_q = count_q.where(cond)
        total = int((await self._session.scalar(count_q)) or 0)
        query = query.order_by(SecurityEvent.last_observed_at.desc()).limit(
            min(max(limit, 1), 500)
        ).offset(max(offset, 0))
        rows = (await self._session.scalars(query)).all()
        return rows, total

    async def get_event(self, event_id: uuid.UUID) -> SecurityEvent:
        row = await self._session.get(SecurityEvent, event_id)
        if row is None:
            raise NotFoundError(f"Security event {event_id} not found.")
        return row

    # ---- helpers -----------------------------------------------------------

    async def _get_source(
        self, source_type: str, cloud_account_id: uuid.UUID | None
    ) -> SecurityEventSource | None:
        return await self._session.scalar(
            select(SecurityEventSource).where(
                SecurityEventSource.source_type == source_type,
                SecurityEventSource.cloud_account_id == cloud_account_id,
            )
        )

    def _source_secret(self, source: SecurityEventSource) -> str:
        if not source.encrypted_secret:
            return ""
        return require_cipher(self._settings).decrypt(source.encrypted_secret)
