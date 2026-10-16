"""Phase 5 models: normalized security events and their sources.

A :class:`SecurityEvent` is the single, source-agnostic representation of a
security-relevant signal (an AWS GuardDuty finding, a CloudTrail event, a new
deterministic scan finding, a CI/CD security failure, a Falco alert, ...). All
ingestion adapters normalize into this shape so correlation, incidents and the AI
investigation layer have one vocabulary to reason over.

Key safety properties:
- ``fingerprint`` is UNIQUE: repeated delivery of the same underlying signal
  bumps ``occurrences`` / ``last_observed_at`` instead of creating duplicates.
- ``verified`` records whether the signal was produced by one of OUR deterministic
  engines (repo/cloud scans) versus merely *reported* by an external source. The
  UI and correlation never conflate "externally reported" with "verified".
- Raw provenance is preserved (``provenance``) but secret values are redacted at
  the ingestion boundary before anything is persisted.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from models.base import GUID, Base


def _now() -> datetime:
    return datetime.now(UTC)


class SecurityEventSource(Base):
    """A registered source of security events + its synchronization health.

    Internal sources (repo/cloud scans) are auto-registered on first use. External
    sources (AWS native, webhook delivered) carry an optional cloud-account link
    and an encrypted shared secret used to authenticate inbound webhooks.
    """

    __tablename__ = "security_event_sources"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    # One of enums.SecurityEventSourceType.
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Optional link to the cloud account this source reports on.
    cloud_account_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=True
    )
    # Fernet ciphertext of a webhook shared secret (HMAC). Never returned.
    encrypted_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Non-secret config (e.g. poll interval overrides, region filters).
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # Health / sync status.
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    last_error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    events_ingested: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "source_type", "cloud_account_id", name="uq_security_source_identity"
        ),
        Index("ix_security_sources_type", "source_type"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<SecurityEventSource {self.source_type} enabled={self.enabled}>"


class SecurityEvent(Base):
    """A normalized, deduplicated security event."""

    __tablename__ = "security_events"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)

    # ---- Provenance / source ----
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("security_event_sources.id", ondelete="SET NULL"), nullable=True
    )
    # The source's own identifier for the signal (ARN of a GuardDuty finding, the
    # CloudTrail eventID, a finding id, ...). Used in the dedup fingerprint.
    source_event_id: Mapped[str] = mapped_column(String(512), nullable=False, default="")

    # ---- Scoping ----
    cloud_account_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=True
    )
    # AWS account number / project identifier (string form for display + grouping).
    account_ref: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    region: Mapped[str] = mapped_column(String(32), nullable=False, default="")

    # ---- Subject ----
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    resource_arn: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    principal: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    # ---- Classification ----
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # ---- Verification + evidence ----
    # True when produced by OUR deterministic engines (repo/cloud scans).
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Related deterministic finding ids (repo Finding or CloudFinding), list[str].
    related_finding_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # Secret-redacted evidence references / normalized fields.
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # Secret-redacted original payload (bounded) for provenance.
    provenance: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # ---- Dedup / lifecycle ----
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    occurrences: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="new")
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )

    first_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    last_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_security_event_fingerprint"),
        Index("ix_security_events_account", "cloud_account_id", "created_at"),
        Index("ix_security_events_status", "status"),
        Index("ix_security_events_resource", "resource_id"),
        Index("ix_security_events_incident", "incident_id"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<SecurityEvent {self.source_type}:{self.event_type} sev={self.severity}>"
