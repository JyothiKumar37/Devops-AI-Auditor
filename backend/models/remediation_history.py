"""Persistence model for remediation history.

Every time a user approves and applies a deterministic fix, an immutable audit
record is written here: what finding was targeted, the patch (diff), whether the
re-scan verified resolution, and a before/after severity snapshot of the scan.

The finding row itself is deleted once a fix is verified, so this table does NOT
foreign-key to `findings` (that would cascade-delete the audit trail). It keys to
the scan and denormalises the finding's identity, so the history survives the
resolution it records.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from models.base import GUID, Base


class RemediationHistory(Base):
    """An audit record of one approved remediation attempt on a finding."""

    __tablename__ = "remediation_history"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    # Denormalised finding identity (no FK: the finding is deleted once resolved).
    finding_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # The finding's severity at the time of remediation.
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")

    applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Rule ids still firing on the patched file after re-scan.
    remaining_rule_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)
    diff: Mapped[str | None] = mapped_column(Text, nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Scan severity snapshot immediately before/after this remediation.
    before_counts: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    after_counts: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_remediation_history_scan_created", "scan_id", "created_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<RemediationHistory scan={self.scan_id} rule={self.rule_id} "
            f"resolved={self.resolved}>"
        )
