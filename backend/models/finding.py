"""Persistence model for scanner findings.

A `Finding` is a single issue reported by a scanner (deterministic rule engine,
Hadolint, Trivy, ...) against a specific repository file. The schema captures the
full evidence trail so findings are actionable and auditable.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base import GUID, Base, TimestampMixin
from models.enums import Confidence, FindingCategory, Severity


class Finding(Base, TimestampMixin):
    """A single issue reported by a scanner against a repository file."""

    __tablename__ = "findings"

    # finding_id
    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    file_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(),
        ForeignKey("repository_files.id", ondelete="CASCADE"),
        nullable=True,
    )

    category: Mapped[FindingCategory] = mapped_column(String(32), nullable=False)
    severity: Mapped[Severity] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[Confidence] = mapped_column(String(16), nullable=False)

    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False, default="")

    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Stable rule identifier (e.g. "DCK001", or a Hadolint/Trivy id).
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # The tool that produced the finding: "docker-rules" | "hadolint" | "trivy".
    scanner: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    scan = relationship("Scan")
    file = relationship("RepositoryFile")

    __table_args__ = (
        Index("ix_findings_scan_id", "scan_id"),
        Index("ix_findings_scan_severity", "scan_id", "severity"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Finding rule={self.rule_id} sev={self.severity} scan={self.scan_id}>"
