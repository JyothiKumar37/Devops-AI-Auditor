"""Persistence models for PR/MR scanning and inbound webhook events.

- ``WebhookEvent`` records every accepted webhook delivery; its unique
  ``delivery_id`` provides idempotency / replay protection.
- ``PullRequest`` tracks a pull/merge request of a connected repository.
- ``PullRequestScan`` stores the deterministic result of one incremental scan
  (new/fixed findings, PR risk, readiness delta, policy outcome).
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


class WebhookEvent(Base):
    """An accepted inbound webhook delivery (deduped by delivery_id)."""

    __tablename__ = "webhook_events"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    delivery_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    repo_full_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    processed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        UniqueConstraint("provider", "delivery_id", name="uq_webhook_delivery"),
        Index("ix_webhook_events_received", "received_at"),
    )


class PullRequest(Base):
    """A pull/merge request of a connected repository."""

    __tablename__ = "pull_requests"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    repo_full_name: Mapped[str] = mapped_column(String(512), nullable=False)
    number: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    author: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    base_ref: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    head_ref: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    web_url: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    # Provider-native id of the auditor's summary comment, for reconciliation
    # (GitLab stores a composite "mr_iid:note_id").
    summary_comment_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "provider", "repo_full_name", "number", name="uq_pull_request_identity"
        ),
        Index("ix_pull_requests_repo", "repo_full_name"),
    )


class PullRequestScan(Base):
    """The deterministic result of one incremental scan of a PR head."""

    __tablename__ = "pull_request_scans"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    pull_request_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("pull_requests.id", ondelete="CASCADE"), nullable=False
    )
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="completed")
    # Deterministic metrics.
    changed_files: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    new_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fixed_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    pr_risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    readiness_before: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    readiness_after: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    # Full detail blobs (new finding list, severity deltas, policy result).
    severity_delta: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    findings_detail: Mapped[list | None] = mapped_column(JSON, nullable=True)
    policy_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    gate_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pass")
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        Index("ix_pr_scans_pr", "pull_request_id", "created_at"),
    )
