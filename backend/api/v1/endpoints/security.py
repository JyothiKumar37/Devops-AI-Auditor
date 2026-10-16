"""Phase 5 security endpoints: events, sources, inbound webhooks, correlation.

Inbound webhooks (``/security/webhooks/{source}``) are called by external senders
and are authenticated by HMAC signature + replay window (not the API key), like
the SCM webhooks. Event/source reads are normal authenticated API endpoints.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Request, status

from api.dependencies import IncidentServiceDep, SecurityServiceDep, SettingsDep
from models.schemas import (
    CorrelateResponse,
    SecurityEventListResponse,
    SecurityEventRead,
    SecuritySourceListResponse,
    SecuritySourceRead,
)

router = APIRouter(prefix="/security", tags=["security"])


def _lower_headers(request: Request) -> dict[str, str]:
    return {k.lower(): v for k, v in request.headers.items()}


@router.get(
    "/events",
    response_model=SecurityEventListResponse,
    summary="List normalized security events",
)
async def list_events(
    service: SecurityServiceDep,
    source_type: str | None = None,
    severity: str | None = None,
    event_status: str | None = None,
    resource_id: str | None = None,
    verified: bool | None = None,
    limit: int = 100,
    offset: int = 0,
) -> SecurityEventListResponse:
    items, total = await service.list_events(
        source_type=source_type, severity=severity, status=event_status,
        resource_id=resource_id, verified=verified, limit=limit, offset=offset,
    )
    return SecurityEventListResponse(
        total=total, returned=len(items),
        items=[SecurityEventRead.model_validate(e) for e in items],
    )


@router.get(
    "/events/{event_id}",
    response_model=SecurityEventRead,
    summary="Get one normalized security event",
)
async def get_event(event_id: uuid.UUID, service: SecurityServiceDep) -> SecurityEventRead:
    return SecurityEventRead.model_validate(await service.get_event(event_id))


@router.get(
    "/sources",
    response_model=SecuritySourceListResponse,
    summary="List registered security event sources + health",
)
async def list_sources(service: SecurityServiceDep) -> SecuritySourceListResponse:
    items = await service.list_sources()
    return SecuritySourceListResponse(
        total=len(items), items=[SecuritySourceRead.model_validate(s) for s in items]
    )


@router.get(
    "/integrations/health",
    summary="Security integration / ingestion health summary",
)
async def integrations_health(service: SecurityServiceDep) -> dict:
    sources = await service.list_sources()
    return {
        "total_sources": len(sources),
        "sources": [
            {
                "source_type": s.source_type,
                "enabled": s.enabled,
                "status": s.last_status,
                "events_ingested": s.events_ingested,
                "last_event_at": s.last_event_at.isoformat() if s.last_event_at else None,
                "last_error": s.last_error,
            }
            for s in sources
        ],
    }


@router.post(
    "/correlate",
    response_model=CorrelateResponse,
    summary="Correlate uncorrelated events into incidents (deterministic)",
)
async def correlate(service_incidents: IncidentServiceDep) -> CorrelateResponse:
    incidents = await service_incidents.correlate_new_events()
    return CorrelateResponse(
        incidents_touched=len(incidents), incident_ids=[i.id for i in incidents]
    )


@router.post(
    "/webhooks/{source}",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive a security webhook (HMAC + replay protected)",
)
async def security_webhook(
    source: str,
    request: Request,
    service: SecurityServiceDep,
    settings: SettingsDep,
    incidents: IncidentServiceDep,
) -> dict:
    body = await request.body()
    result = await service.ingest_webhook(source, _lower_headers(request), body)
    # Correlate immediately so an incident is available without waiting for the
    # scheduled sweep (idempotent either way).
    touched = await incidents.correlate_new_events()
    return {
        "accepted": True,
        "created": result.created_count,
        "deduplicated": result.deduplicated_count,
        "incidents_touched": len(touched),
    }
