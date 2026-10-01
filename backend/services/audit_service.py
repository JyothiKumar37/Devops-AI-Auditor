"""Recording and querying of audit log entries for sensitive actions.

``record`` is best-effort and defensive: it scrubs any known-secret keys from the
supplied detail so tokens/URLs/passwords can never be persisted, and it never
raises into the caller (an audit failure must not break the operation).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.logging import get_logger
from models.audit import AuditLog

logger = get_logger(__name__)

# Keys whose values must never be written to the audit log, matched case-
# insensitively as substrings (so "access_token", "webhook_url" etc. are caught).
_SECRET_KEY_HINTS = (
    "token",
    "secret",
    "password",
    "passwd",
    "url",
    "key",
    "credential",
    "authorization",
)
_REDACTED = "***redacted***"


def scrub(detail: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a copy of ``detail`` with any secret-looking values redacted."""
    if not detail:
        return detail
    clean: dict[str, Any] = {}
    for key, value in detail.items():
        lowered = key.lower()
        if any(hint in lowered for hint in _SECRET_KEY_HINTS):
            clean[key] = _REDACTED
        elif isinstance(value, dict):
            clean[key] = scrub(value)
        else:
            clean[key] = value
    return clean


class AuditService:
    """Append-only audit trail for security-relevant operations."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record(
        self,
        action: str,
        *,
        resource_type: str = "",
        resource_id: str | None = None,
        actor: str = "api",
        status: str = "success",
        detail: dict[str, Any] | None = None,
    ) -> AuditLog | None:
        """Persist one audit entry. Never raises - returns None on failure."""
        try:
            entry = AuditLog(
                id=uuid.uuid4(),
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                actor=actor,
                status=status,
                detail=scrub(detail),
            )
            self._session.add(entry)
            await self._session.flush()
            return entry
        except Exception as exc:  # noqa: BLE001 - auditing must never break the action
            logger.warning("audit_record_failed", action=action, error=str(exc))
            return None

    async def list_logs(
        self,
        *,
        action: str | None = None,
        resource_type: str | None = None,
        limit: int = 100,
    ) -> Sequence[AuditLog]:
        query = select(AuditLog).order_by(AuditLog.created_at.desc())
        if action:
            query = query.where(AuditLog.action == action)
        if resource_type:
            query = query.where(AuditLog.resource_type == resource_type)
        query = query.limit(min(max(limit, 1), 500))
        return (await self._session.scalars(query)).all()
