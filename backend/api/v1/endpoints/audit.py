"""Audit log query endpoint (read-only history of sensitive actions)."""

from __future__ import annotations

from fastapi import APIRouter

from api.dependencies import DbSessionDep
from models.schemas import AuditLogListResponse, AuditLogRead
from services.audit_service import AuditService

router = APIRouter(prefix="/audit-logs", tags=["audit"])


@router.get("", response_model=AuditLogListResponse, summary="List audit log entries")
async def list_audit_logs(
    session: DbSessionDep,
    action: str | None = None,
    resource_type: str | None = None,
    limit: int = 100,
) -> AuditLogListResponse:
    service = AuditService(session)
    items = await service.list_logs(
        action=action, resource_type=resource_type, limit=limit
    )
    return AuditLogListResponse(
        total=len(items), items=[AuditLogRead.model_validate(i) for i in items]
    )
