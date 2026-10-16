"""Phase 4 cloud models: AWS accounts, assets, relationships, snapshots, drift.

The platform connects to AWS via STS AssumeRole (read-only) - it NEVER stores
long-lived AWS access keys. The role ARN is stored in plaintext (not a secret,
and shown in the UI); the external id (the confused-deputy shared secret) is
stored as Fernet ciphertext, mirroring how SCM tokens are handled.

Cloud findings deliberately use a dedicated ``CloudFinding`` table rather than the
repository ``Finding`` table: a cloud finding belongs to an account + resource
(not a repo scan/file), needs account-scoped exceptions, and must not perturb the
Phase 1 schema. The deterministic finding *architecture* (RuleFinding DTO,
severity/confidence enums, readiness/posture scoring, fingerprints) is still
reused - only the persistence row differs.
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


class CloudAccount(Base):
    """A connected AWS account (accessed read-only via STS AssumeRole)."""

    __tablename__ = "cloud_accounts"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    provider: Mapped[str] = mapped_column(String(16), nullable=False, default="aws")
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    # The 12-digit AWS account id, derived from sts:GetCallerIdentity (authoritative;
    # never trusted from the client).
    account_id: Mapped[str] = mapped_column(String(32), nullable=False)
    # Read-only role to assume. Not a secret; shown in the UI.
    role_arn: Mapped[str] = mapped_column(String(512), nullable=False)
    # Fernet ciphertext of the external id (confused-deputy shared secret). Nullable.
    encrypted_external_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Regions to scan (list[str]).
    regions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    status_detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    __table_args__ = (
        UniqueConstraint("provider", "account_id", name="uq_cloud_account_provider_id"),
        Index("ix_cloud_accounts_account_id", "account_id"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<CloudAccount {self.provider}:{self.account_id} status={self.status}>"


class CloudSnapshot(Base):
    """One synchronization run of an account's cloud state (point in time)."""

    __tablename__ = "cloud_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    regions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_cloud_snapshots_account", "account_id", "created_at"),)


class CloudAsset(Base):
    """A discovered AWS resource (metadata only - never secret values)."""

    __tablename__ = "cloud_assets"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
    )
    service: Mapped[str] = mapped_column(String(32), nullable=False)  # ec2|vpc|s3|rds|iam|eks|...
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    # Natural resource id (e.g. i-123, sg-abc, bucket name). Unique per account+service.
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False)
    arn: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    name: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    region: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    # Internet exposure classification: none|private|public|unknown.
    exposure: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    tags: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # Non-secret resource attributes used by rules/graph (e.g. SG rules, public flags).
    attributes: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    first_discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    last_synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "account_id", "service", "resource_id", name="uq_cloud_asset_identity"
        ),
        Index("ix_cloud_assets_account_service", "account_id", "service"),
        Index("ix_cloud_assets_region", "account_id", "region"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<CloudAsset {self.service}:{self.resource_id} region={self.region}>"


class CloudRelationship(Base):
    """A directed, evidence-backed edge between two cloud assets (for the graph)."""

    __tablename__ = "cloud_relationships"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
    )
    source_resource_id: Mapped[str] = mapped_column(String(512), nullable=False)
    target_resource_id: Mapped[str] = mapped_column(String(512), nullable=False)
    # routes-to | attached-to | allows | uses | connects-to | exposes
    relation: Mapped[str] = mapped_column(String(32), nullable=False)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_cloud_rel_account", "account_id"),
        Index("ix_cloud_rel_source", "account_id", "source_resource_id"),
    )


class CloudFinding(Base):
    """A deterministic cloud security finding (own table; reuses finding semantics)."""

    __tablename__ = "cloud_findings"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
    )
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True)
    service: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    region: Mapped[str] = mapped_column(String(32), nullable=False, default="")

    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scanner: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="high")
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Stable fingerprint (rule_id|resource_id|evidence) for exceptions/change diffs.
    fingerprint: Mapped[str] = mapped_column(String(600), nullable=False, index=True)
    # Compliance control ids this finding maps to (list[str]).
    compliance: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        Index("ix_cloud_findings_account", "account_id"),
        Index("ix_cloud_findings_account_sev", "account_id", "severity"),
        Index("ix_cloud_findings_resource", "account_id", "resource_id"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<CloudFinding {self.rule_id} {self.severity} {self.resource_id}>"


class CloudDrift(Base):
    """Terraform (expected) vs AWS (actual) drift status for a resource."""

    __tablename__ = "cloud_drift"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
    )
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False)
    service: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    terraform_address: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # IN_SYNC | DRIFTED | UNKNOWN | NOT_MANAGED
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    expected: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    actual: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    differences: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (Index("ix_cloud_drift_account", "account_id"),)


class ComplianceException(Base):
    """An accepted exception to a compliance control (with optional expiry).

    Reuses the suppression philosophy but scoped to a cloud account + control (and
    optionally a specific resource). Expired exceptions are ignored. There is
    always an audit trail - no silent permanent exceptions.
    """

    __tablename__ = "compliance_exceptions"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
    )
    framework: Mapped[str] = mapped_column(String(32), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # Optional: scope the exception to a single resource; null = whole control.
    resource_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # accept_risk | false_positive | not_applicable | compensating_control
    reason: Mapped[str] = mapped_column(String(32), nullable=False)
    owner: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (Index("ix_compliance_exc_account", "account_id", "framework"),)

    def is_active(self, now: datetime) -> bool:
        if self.expires_at is None:
            return True
        expires = self.expires_at
        # SQLite returns naive datetimes for DateTime(timezone=True); normalize so
        # the comparison with an aware `now` never raises.
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=now.tzinfo)
        return expires > now


class CloudChange(Base):
    """A detected change in a resource between two synchronizations."""

    __tablename__ = "cloud_changes"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
    )
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True)
    service: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    change_type: Mapped[str] = mapped_column(String(16), nullable=False)  # added|removed|modified
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    risk_significant: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (Index("ix_cloud_changes_account", "account_id", "created_at"),)
