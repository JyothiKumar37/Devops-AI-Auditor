"""Persistence for AI investigation sessions (Phase 3).

One row captures a completed investigation: the question, the evidence-grounded
answer, the structured citations/evidence, and a safe high-level execution trace
(tool actions + observations only - never raw chain-of-thought). This lets users
reopen past investigations and inspect how the agent reached its conclusion.

A single table (with JSON blobs for evidence/trace/citations) is sufficient; we
deliberately avoid proliferating per-message/per-tool-call tables.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from models.base import GUID, Base


def _now() -> datetime:
    return datetime.now(UTC)


class AIInvestigation(Base):
    """A persisted, evidence-grounded AI investigation session."""

    __tablename__ = "ai_investigations"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    # scope: scan | finding | repository
    scope: Mapped[str] = mapped_column(String(16), nullable=False, default="scan")
    scan_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True)
    repository_name: Mapped[str] = mapped_column(String(512), nullable=False, default="")

    question: Mapped[str] = mapped_column(Text, nullable=False)
    answer: Mapped[str] = mapped_column(Text, nullable=False, default="")
    root_cause: Mapped[str] = mapped_column(Text, nullable=False, default="")
    impact: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    label: Mapped[str] = mapped_column(String(32), nullable=False, default="AI Insight")

    recommendations: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    citations: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    trace: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    ai_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tool_calls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hallucination_guard_triggered: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        Index("ix_ai_investigations_scan", "scan_id", "created_at"),
        Index("ix_ai_investigations_repo", "repository_name", "created_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AIInvestigation scope={self.scope} scan={self.scan_id} conf={self.confidence}>"
