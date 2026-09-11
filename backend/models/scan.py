"""Persistence models for repository scans and their indexed files.

A `Scan` records an ingestion/audit request and its lifecycle. `RepositoryFile`
records metadata for each file discovered in the ingested repository. Actual
finding storage and scanner-specific results are added in later stages.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, BigInteger, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base import GUID, Base, TimestampMixin
from models.enums import ScanStatus, SourceType


class Scan(Base, TimestampMixin):
    """A single repository ingestion/audit request and its lifecycle status."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    repository_name: Mapped[str] = mapped_column(String(512), nullable=False)
    source_type: Mapped[SourceType] = mapped_column(String(16), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        String(32),
        default=ScanStatus.PENDING,
        nullable=False,
        index=True,
    )
    # created_at is provided by TimestampMixin.
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Cross-stack entity index produced during ingestion, used for correlation.
    correlation_index: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    files: Mapped[list[RepositoryFile]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Scan id={self.id} status={self.status} name={self.repository_name!r}>"


class RepositoryFile(Base):
    """Metadata for a single file discovered within an ingested repository."""

    __tablename__ = "repository_files"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Relative POSIX path within the repository (never an absolute/host path).
    path: Mapped[str] = mapped_column(String(4096), nullable=False)
    # Detected artifact category (e.g. "dockerfile") or "other".
    file_type: Mapped[str] = mapped_column(String(32), nullable=False, default="other")
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # Hex-encoded SHA-256 of the file contents.
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    # Text content for reasonably sized text files (used by the UI code viewer);
    # None for binary/oversized files.
    content: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="files")

    __table_args__ = (Index("ix_repository_files_scan_id", "scan_id"),)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<RepositoryFile scan_id={self.scan_id} path={self.path!r}>"
