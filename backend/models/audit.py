"""Audit log for sensitive, state-changing actions.

Records WHO (best-effort actor), WHAT (action + resource), and the OUTCOME of
security-relevant operations: connecting/disconnecting integrations, policy
changes, notification channel changes, and webhook authentication failures.

CRITICAL: audit detail must NEVER contain secrets (tokens, webhook URLs, SMTP
passwords). The ``AuditService`` scrubs known-sensitive keys defensively, but
callers are expected to pass only non-secret metadata.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from models.base import GUID, Base


def _now() -> datetime:
    return datetime.now(UTC)


class AuditLog(Base):
    """One immutable record of a sensitive action (append-only in practice)."""

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    # Dotted action name, e.g. "integration.connect", "policy.update".
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Best-effort identity. Single-tenant, so usually "api" or a source IP.
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="api")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="success")
    # Non-secret structured context (scrubbed of known secret keys).
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_created_at", "created_at"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AuditLog {self.action} {self.resource_type}:{self.resource_id} {self.status}>"
