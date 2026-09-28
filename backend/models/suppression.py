"""Persistence model for finding suppressions (baselines).

A `Suppression` records a user's decision to baseline a finding - marking it a
false positive, an accepted risk, or won't-fix. Suppressions are scoped to a
**repository** and keyed by a stable **fingerprint** (rule + file + evidence),
independent of any single scan, so the decision automatically carries across
future scans of the same repository.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from models.base import GUID, Base, TimestampMixin
from models.enums import SuppressionReason


class Suppression(Base, TimestampMixin):
    """A user decision to baseline a finding across a repository's scans."""

    __tablename__ = "suppressions"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    # Baseline scope: all scans of this repository share suppressions.
    repository_name: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    # Stable identity of the finding across scans: rule_id | file path | evidence.
    fingerprint: Mapped[str] = mapped_column(String(512), nullable=False, index=True)

    # Denormalised for display / listing without recomputation.
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    reason: Mapped[SuppressionReason] = mapped_column(String(32), nullable=False)
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        UniqueConstraint("repository_name", "fingerprint", name="uq_suppression_repo_fp"),
        Index("ix_suppressions_repo_fp", "repository_name", "fingerprint"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Suppression repo={self.repository_name} rule={self.rule_id}>"
