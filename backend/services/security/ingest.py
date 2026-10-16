"""Security event ingestion: dedup, idempotent upsert, source health.

Ingestion is idempotent by construction: the normalized event's content
fingerprint is UNIQUE, so a repeated signal bumps ``occurrences`` /
``last_observed_at`` on the existing row rather than inserting a duplicate (which
is what prevents duplicate incidents downstream). Out-of-order deliveries are
handled by keeping the earliest ``first_observed_at`` and the latest
``last_observed_at``.

All persisted text is already secret-redacted (:meth:`NormalizedEvent.redacted`).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.logging import get_logger
from models.security import SecurityEvent, SecurityEventSource
from services.security.normalize import NormalizedEvent

logger = get_logger(__name__)


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class IngestResult:
    """Outcome of ingesting a batch of normalized events."""

    created: list[SecurityEvent]
    deduplicated: list[SecurityEvent]

    @property
    def created_count(self) -> int:
        return len(self.created)

    @property
    def deduplicated_count(self) -> int:
        return len(self.deduplicated)

    @property
    def all_events(self) -> list[SecurityEvent]:
        return [*self.created, *self.deduplicated]


class SecurityIngestService:
    """Normalizes-in, deduplicates, and persists security events."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    async def ingest(self, event: NormalizedEvent) -> tuple[SecurityEvent, bool]:
        """Ingest a single normalized event. Returns ``(row, created)``.

        ``created`` is False when the event deduplicated onto an existing row.
        """
        ev = event.redacted()
        fingerprint = ev.fingerprint()
        observed = ev.observed_at or _now()

        source = await self._ensure_source(ev.source_type, ev.cloud_account_id)

        existing = await self._session.scalar(
            select(SecurityEvent).where(SecurityEvent.fingerprint == fingerprint)
        )
        if existing is not None:
            existing.occurrences += 1
            # Out-of-order safe: widen the observation window.
            if observed > self._aware(existing.last_observed_at):
                existing.last_observed_at = observed
            if observed < self._aware(existing.first_observed_at):
                existing.first_observed_at = observed
            # Union related deterministic finding ids.
            merged = list(dict.fromkeys([*existing.related_finding_ids, *ev.related_finding_ids]))
            existing.related_finding_ids = merged
            await self._touch_source(source, observed)
            await self._session.flush()
            return existing, False

        row = SecurityEvent(
            id=uuid.uuid4(),
            source_type=ev.source_type,
            source_id=source.id if source else None,
            source_event_id=ev.source_event_id,
            cloud_account_id=ev.cloud_account_id,
            account_ref=ev.account_ref,
            region=ev.region,
            resource_id=ev.resource_id,
            resource_arn=ev.resource_arn,
            principal=ev.principal,
            source_ip=ev.source_ip,
            category=ev.normalized_category(),
            event_type=ev.event_type,
            severity=ev.severity,
            confidence=ev.confidence,
            title=ev.title,
            description=ev.description,
            verified=ev.verified,
            related_finding_ids=ev.related_finding_ids,
            evidence=ev.evidence,
            provenance=ev.provenance,
            fingerprint=fingerprint,
            occurrences=1,
            status="new",
            first_observed_at=observed,
            last_observed_at=observed,
        )
        self._session.add(row)
        await self._touch_source(source, observed, ingested=True)
        await self._session.flush()
        logger.info(
            "security_event_ingested",
            source=ev.source_type,
            category=ev.category,
            severity=ev.severity,
            verified=ev.verified,
        )
        return row, True

    async def ingest_many(self, events: list[NormalizedEvent]) -> IngestResult:
        created: list[SecurityEvent] = []
        deduped: list[SecurityEvent] = []
        for event in events:
            row, is_new = await self.ingest(event)
            (created if is_new else deduped).append(row)
        return IngestResult(created=created, deduplicated=deduped)

    # ---- source registration + health ------------------------------------

    async def _ensure_source(
        self, source_type: str, cloud_account_id: uuid.UUID | None
    ) -> SecurityEventSource:
        existing = await self._session.scalar(
            select(SecurityEventSource).where(
                SecurityEventSource.source_type == source_type,
                SecurityEventSource.cloud_account_id == cloud_account_id,
            )
        )
        if existing is not None:
            return existing
        source = SecurityEventSource(
            id=uuid.uuid4(),
            source_type=source_type,
            name=source_type,
            enabled=True,
            cloud_account_id=cloud_account_id,
            config={},
            last_status="ok",
        )
        self._session.add(source)
        await self._session.flush()
        return source

    async def _touch_source(
        self, source: SecurityEventSource, observed: datetime, *, ingested: bool = False
    ) -> None:
        source.last_polled_at = _now()
        source.last_event_at = observed
        source.last_status = "ok"
        source.last_error = ""
        if ingested:
            source.events_ingested += 1

    @staticmethod
    def _aware(value: datetime) -> datetime:
        """Normalize a possibly-naive (SQLite) datetime to aware UTC."""
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value
