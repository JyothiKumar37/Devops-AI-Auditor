"""Controlled, read-only incident investigation tools (Phase 5).

These give the AI agent evidence about ONE authorized incident: its summary,
member security events (with correlation rationale), timeline, affected
resources, and containment history. They return metadata only, are secret-
redacted, and are scope-enforced via ``ctx.authorizes_incident``. Deeper cloud
evidence (resource metadata, IAM, drift, network graph, compliance) is available
through the Phase 4 cloud tools, which the incident engine also registers and
authorizes for the incident's cloud account.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import Field
from sqlalchemy import select

from agents.investigation.redaction import redact_secrets
from agents.investigation.tools.base import (
    InvestigationTool,
    ToolArgs,
    ToolContext,
    ToolError,
    ToolResult,
    clamp_limit,
)
from agents.reasoning.sanitize import neutralize
from models.enums import Severity
from models.incident import (
    ContainmentExecution,
    ContainmentPlan,
    Incident,
    IncidentEvent,
    IncidentResource,
    IncidentTimelineEntry,
)
from models.security import SecurityEvent


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _event_summary(ev: SecurityEvent) -> dict[str, Any]:
    return {
        "event_id": str(ev.id),
        "source": ev.source_type,
        "category": ev.category,
        "event_type": neutralize(ev.event_type, max_length=120),
        "severity": ev.severity,
        "verified": ev.verified,
        "resource_id": ev.resource_id,
        "principal": ev.principal,
        "source_ip": ev.source_ip,
        "title": neutralize(ev.title, max_length=200),
        "related_finding_ids": list(ev.related_finding_ids or []),
        "first_observed_at": str(ev.first_observed_at),
    }


class _IncidentArgs(ToolArgs):
    incident_id: uuid.UUID = Field(description="The incident under investigation.")


async def _load_incident(ctx: ToolContext, incident_id: uuid.UUID) -> Incident:
    incident = await ctx.session.get(Incident, incident_id)
    if incident is None:
        raise ToolError(f"Incident {incident_id} not found.", code="not_found")
    return incident


class GetIncidentTool(InvestigationTool):
    name = "get_incident"
    description = "Incident summary: status, severity, affected resources, counts, hypothesis."
    args_schema = _IncidentArgs

    async def _run(self, ctx: ToolContext, args: _IncidentArgs) -> ToolResult:  # type: ignore[override]
        incident = await _load_incident(ctx, args.incident_id)
        resources = (
            await ctx.session.scalars(
                select(IncidentResource).where(
                    IncidentResource.incident_id == args.incident_id
                )
            )
        ).all()
        return ToolResult(
            data={
                "incident_id": str(incident.id),
                "title": neutralize(incident.title, max_length=300),
                "status": incident.status,
                "severity": incident.severity,
                "priority": incident.priority,
                "risk_score": incident.risk_score,
                "account_ref": incident.account_ref,
                "event_count": incident.event_count,
                "root_cause_hypothesis": neutralize(
                    incident.root_cause_hypothesis, max_length=600
                ),
                "resources": [
                    {"resource_id": r.resource_id, "service": r.service,
                     "region": r.region, "exposure": r.exposure}
                    for r in resources
                ],
            },
            returned=1,
        )


class SearchEventsArgs(_IncidentArgs):
    severity: str | None = Field(default=None, description="Filter: critical|high|medium|low")
    verified_only: bool = Field(default=False, description="Only verified events.")
    limit: int = Field(default=50)


class SearchSecurityEventsTool(InvestigationTool):
    name = "search_security_events"
    description = (
        "List the incident's member security events (correlated signals), severity-"
        "sorted; filter by severity or verified-only."
    )
    args_schema = SearchEventsArgs

    async def _run(self, ctx: ToolContext, args: SearchEventsArgs) -> ToolResult:  # type: ignore[override]
        query = select(SecurityEvent).where(SecurityEvent.incident_id == args.incident_id)
        if args.severity:
            query = query.where(SecurityEvent.severity == args.severity)
        if args.verified_only:
            query = query.where(SecurityEvent.verified.is_(True))
        rows = list((await ctx.session.scalars(query)).all())
        rows.sort(key=lambda e: -_sev_rank(e.severity))
        total = len(rows)
        limit = clamp_limit(args.limit)
        data = [_event_summary(e) for e in rows[:limit]]
        return ToolResult(
            data=data, returned=len(data), total_available=total, truncated=total > limit
        )


class _EventArgs(_IncidentArgs):
    event_id: uuid.UUID = Field(description="A security event id belonging to the incident.")


class GetSecurityEventTool(InvestigationTool):
    name = "get_security_event"
    description = "Full detail for one of the incident's member events (secret-redacted)."
    args_schema = _EventArgs

    async def _run(self, ctx: ToolContext, args: _EventArgs) -> ToolResult:  # type: ignore[override]
        event = await ctx.session.get(SecurityEvent, args.event_id)
        if event is None or event.incident_id != args.incident_id:
            raise ToolError(
                f"Event {args.event_id} is not part of incident {args.incident_id}.",
                code="not_found",
            )
        link = await ctx.session.scalar(
            select(IncidentEvent).where(
                IncidentEvent.incident_id == args.incident_id,
                IncidentEvent.event_id == args.event_id,
            )
        )
        data = _event_summary(event)
        data["description"] = neutralize(redact_secrets(event.description), max_length=600)
        data["evidence"] = _redact(event.evidence)
        data["correlation_rationale"] = link.rationale if link else ""
        data["correlation_signal"] = link.correlation_signal if link else ""
        return ToolResult(data=data, returned=1)


class GetIncidentTimelineTool(InvestigationTool):
    name = "get_incident_timeline"
    description = (
        "The incident's chronological timeline. Each entry has an evidence_class: "
        "confirmed | reported | inferred | hypothesis | action."
    )
    args_schema = _IncidentArgs

    async def _run(self, ctx: ToolContext, args: _IncidentArgs) -> ToolResult:  # type: ignore[override]
        rows = (
            await ctx.session.scalars(
                select(IncidentTimelineEntry)
                .where(IncidentTimelineEntry.incident_id == args.incident_id)
                .order_by(IncidentTimelineEntry.occurred_at.asc())
            )
        ).all()
        data = [
            {
                "entry_type": t.entry_type,
                "title": neutralize(t.title, max_length=200),
                "evidence_class": t.evidence_class,
                "occurred_at": str(t.occurred_at),
                "detail": _redact(t.detail),
            }
            for t in rows
        ]
        return ToolResult(data=data, returned=len(data))


class GetRemediationHistoryTool(InvestigationTool):
    name = "get_remediation_history"
    description = "Past containment plans + executions for the incident (approval/verification)."
    args_schema = _IncidentArgs

    async def _run(self, ctx: ToolContext, args: _IncidentArgs) -> ToolResult:  # type: ignore[override]
        plans = (
            await ctx.session.scalars(
                select(ContainmentPlan).where(ContainmentPlan.incident_id == args.incident_id)
            )
        ).all()
        data = []
        for plan in plans:
            execs = (
                await ctx.session.scalars(
                    select(ContainmentExecution).where(
                        ContainmentExecution.plan_id == plan.id
                    )
                )
            ).all()
            data.append(
                {
                    "plan_id": str(plan.id),
                    "title": neutralize(plan.title, max_length=200),
                    "capability": plan.capability,
                    "status": plan.status,
                    "executions": [
                        {"status": e.status, "verification": _redact(e.verification)}
                        for e in execs
                    ],
                }
            )
        return ToolResult(data=data, returned=len(data))


def _sev_rank(value: str) -> int:
    try:
        return Severity(value).rank
    except ValueError:
        return 0
