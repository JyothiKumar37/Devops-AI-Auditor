"""Phase 5 incident endpoints: lifecycle, timeline, events, notes.

Status transitions are validated server-side (see IncidentService). AI
investigation, relationship graph and containment plans are mounted by their own
milestones (M5/M6/M8) under this same ``/incidents`` prefix.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from api.dependencies import (
    ContainmentServiceDep,
    IncidentServiceDep,
    InvestigationServiceDep,
)
from models.schemas import (
    ContainmentPlanListResponse,
    ContainmentPlanRead,
    IncidentCreateRequest,
    IncidentDetail,
    IncidentEventRead,
    IncidentInvestigationRead,
    IncidentListResponse,
    IncidentNoteCreateRequest,
    IncidentNoteRead,
    IncidentRead,
    IncidentResourceRead,
    IncidentTimelineEntryRead,
    IncidentTransitionRequest,
    IncidentUpdateRequest,
    InvestigationRequest,
    InvestigationResponse,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])


async def _detail(service: IncidentServiceDep, incident_id: uuid.UUID) -> IncidentDetail:
    incident = await service.get(incident_id)
    events = await service.events_for(incident_id)
    rationale = await service.rationale_for_events(incident_id)
    resources = await service.resources_for(incident_id)
    timeline = await service.timeline_for(incident_id)
    notes = await service.notes_for(incident_id)

    event_items = []
    for ev in events:
        item = IncidentEventRead.model_validate(ev)
        meta = rationale.get(str(ev.id), {})
        item.rationale = meta.get("rationale", "")
        item.correlation_signal = meta.get("signal", "")
        event_items.append(item)

    detail = IncidentDetail.model_validate(incident)
    detail.events = event_items
    detail.resources = [IncidentResourceRead.model_validate(r) for r in resources]
    detail.timeline = [IncidentTimelineEntryRead.model_validate(t) for t in timeline]
    detail.notes = [IncidentNoteRead.model_validate(n) for n in notes]
    detail.risk_rationale = dict(incident.risk_rationale or {})
    return detail


@router.get("", response_model=IncidentListResponse, summary="List incidents")
async def list_incidents(
    service: IncidentServiceDep,
    incident_status: str | None = None,
    severity: str | None = None,
    owner: str | None = None,
    unassigned: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> IncidentListResponse:
    items, total = await service.list_incidents(
        status=incident_status, severity=severity, owner=owner,
        unassigned=unassigned or None, limit=limit, offset=offset,
    )
    return IncidentListResponse(
        total=total, returned=len(items),
        items=[IncidentRead.model_validate(i) for i in items],
    )


@router.post(
    "",
    response_model=IncidentDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create an incident manually from existing events",
)
async def create_incident(
    body: IncidentCreateRequest, service: IncidentServiceDep
) -> IncidentDetail:
    incident = await service.create_manual(
        event_ids=body.event_ids, title=body.title, description=body.description
    )
    return await _detail(service, incident.id)


@router.get("/{incident_id}", response_model=IncidentDetail, summary="Get an incident")
async def get_incident(incident_id: uuid.UUID, service: IncidentServiceDep) -> IncidentDetail:
    return await _detail(service, incident_id)


@router.patch(
    "/{incident_id}", response_model=IncidentRead, summary="Update incident fields"
)
async def update_incident(
    incident_id: uuid.UUID, body: IncidentUpdateRequest, service: IncidentServiceDep
) -> IncidentRead:
    incident = await service.update(
        incident_id,
        owner=body.owner,
        root_cause_hypothesis=body.root_cause_hypothesis,
        resolution_summary=body.resolution_summary,
    )
    return IncidentRead.model_validate(incident)


@router.post(
    "/{incident_id}/transition",
    response_model=IncidentRead,
    summary="Transition an incident's status (validated)",
)
async def transition_incident(
    incident_id: uuid.UUID, body: IncidentTransitionRequest, service: IncidentServiceDep
) -> IncidentRead:
    incident = await service.transition(
        incident_id, body.status, actor=body.actor, note=body.note
    )
    return IncidentRead.model_validate(incident)


@router.get(
    "/{incident_id}/timeline",
    response_model=list[IncidentTimelineEntryRead],
    summary="Get an incident's timeline",
)
async def incident_timeline(
    incident_id: uuid.UUID, service: IncidentServiceDep
) -> list[IncidentTimelineEntryRead]:
    await service.get(incident_id)
    return [
        IncidentTimelineEntryRead.model_validate(t)
        for t in await service.timeline_for(incident_id)
    ]


@router.get(
    "/{incident_id}/relationships",
    summary="Incident relationship graph (confirmed facts vs inferred links)",
)
async def incident_relationships(
    incident_id: uuid.UUID, service: IncidentServiceDep
) -> dict:
    return await service.build_incident_graph(incident_id)


@router.get(
    "/{incident_id}/events",
    response_model=list[IncidentEventRead],
    summary="Get an incident's member events (with correlation rationale)",
)
async def incident_events(
    incident_id: uuid.UUID, service: IncidentServiceDep
) -> list[IncidentEventRead]:
    await service.get(incident_id)
    events = await service.events_for(incident_id)
    rationale = await service.rationale_for_events(incident_id)
    out = []
    for ev in events:
        item = IncidentEventRead.model_validate(ev)
        meta = rationale.get(str(ev.id), {})
        item.rationale = meta.get("rationale", "")
        item.correlation_signal = meta.get("signal", "")
        out.append(item)
    return out


@router.get(
    "/{incident_id}/notes",
    response_model=list[IncidentNoteRead],
    summary="List incident notes",
)
async def list_notes(
    incident_id: uuid.UUID, service: IncidentServiceDep
) -> list[IncidentNoteRead]:
    await service.get(incident_id)
    return [IncidentNoteRead.model_validate(n) for n in await service.notes_for(incident_id)]


@router.post(
    "/{incident_id}/notes",
    response_model=IncidentNoteRead,
    status_code=status.HTTP_201_CREATED,
    summary="Add a note to an incident",
)
async def add_note(
    incident_id: uuid.UUID, body: IncidentNoteCreateRequest, service: IncidentServiceDep
) -> IncidentNoteRead:
    note = await service.add_note(incident_id, body=body.body, author=body.author)
    return IncidentNoteRead.model_validate(note)


@router.post(
    "/{incident_id}/remediation-plans",
    response_model=ContainmentPlanListResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate deterministic containment/remediation plans for an incident",
)
async def generate_remediation_plans(
    incident_id: uuid.UUID, service: ContainmentServiceDep
) -> ContainmentPlanListResponse:
    plans = await service.generate_plans(incident_id)
    return ContainmentPlanListResponse(
        total=len(plans), items=[ContainmentPlanRead.model_validate(p) for p in plans]
    )


@router.get(
    "/{incident_id}/remediation-plans",
    response_model=ContainmentPlanListResponse,
    summary="List an incident's containment/remediation plans",
)
async def list_remediation_plans(
    incident_id: uuid.UUID, service: ContainmentServiceDep
) -> ContainmentPlanListResponse:
    plans = await service.list_plans(incident_id)
    return ContainmentPlanListResponse(
        total=len(plans), items=[ContainmentPlanRead.model_validate(p) for p in plans]
    )


@router.post(
    "/{incident_id}/investigations",
    response_model=InvestigationResponse,
    summary="Investigate an incident with the AI agent (read-only, evidence-grounded)",
)
async def investigate_incident(
    incident_id: uuid.UUID,
    body: InvestigationRequest,
    service: InvestigationServiceDep,
) -> InvestigationResponse:
    result = await service.investigate_incident(incident_id, body.question)
    return InvestigationResponse.model_validate(result.to_dict())


@router.get(
    "/{incident_id}/investigations",
    response_model=list[IncidentInvestigationRead],
    summary="List past AI investigations for an incident",
)
async def list_incident_investigations(
    incident_id: uuid.UUID, service: InvestigationServiceDep
) -> list[IncidentInvestigationRead]:
    rows = await service.list_incident_investigations(incident_id)
    return [IncidentInvestigationRead.model_validate(r) for r in rows]
