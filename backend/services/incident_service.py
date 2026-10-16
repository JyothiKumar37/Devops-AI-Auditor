"""Incident orchestration: deterministic correlation of events into incidents.

This service turns normalized :class:`SecurityEvent` rows into
:class:`Incident` rows by folding events that share an explainable linkage
(see :mod:`services.security.correlation`) into the same OPEN incident, within a
bounded time window. Every attachment records the matched signal + a
human-readable rationale (``IncidentEvent.rationale``) and a confirmed timeline
entry, so a grouping is always auditable. Repeated/duplicate events never create
duplicate incidents (events dedupe at ingest; incidents reuse the open match).

M4 adds the lifecycle (status transitions) + query/CRUD methods on top of this.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.reasoning.sanitize import neutralize
from core.config import Settings
from core.exceptions import ConflictError, NotFoundError, ValidationError
from core.logging import get_logger
from models.cloud import CloudRelationship, ComplianceException
from models.enums import IncidentStatus, Severity
from models.incident import (
    Incident,
    IncidentEvent,
    IncidentNote,
    IncidentResource,
    IncidentTimelineEntry,
)
from models.security import SecurityEvent
from services.security import correlation
from services.security.prioritization import compute_priority

logger = get_logger(__name__)

# Validated incident lifecycle transitions. Terminal states may be reopened to
# INVESTIGATING (operational reality) but no other backward moves are allowed.
_S = IncidentStatus
_TRANSITIONS: dict[str, set[IncidentStatus]] = {
    _S.NEW.value: {_S.TRIAGING, _S.INVESTIGATING, _S.FALSE_POSITIVE, _S.ACCEPTED_RISK},
    _S.TRIAGING.value: {_S.INVESTIGATING, _S.FALSE_POSITIVE, _S.ACCEPTED_RISK},
    _S.INVESTIGATING.value: {
        _S.CONTAINMENT_PLANNED, _S.RESOLVED, _S.FALSE_POSITIVE, _S.ACCEPTED_RISK,
    },
    _S.CONTAINMENT_PLANNED.value: {_S.CONTAINMENT_APPROVED, _S.INVESTIGATING},
    _S.CONTAINMENT_APPROVED.value: {_S.CONTAINED, _S.INVESTIGATING},
    _S.CONTAINED.value: {_S.RESOLVED, _S.INVESTIGATING},
    _S.RESOLVED.value: {_S.INVESTIGATING},
    _S.FALSE_POSITIVE.value: {_S.INVESTIGATING},
    _S.ACCEPTED_RISK.value: {_S.INVESTIGATING},
}
_TERMINAL = frozenset({_S.RESOLVED, _S.FALSE_POSITIVE, _S.ACCEPTED_RISK})


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _sev_rank(value: str) -> int:
    try:
        return Severity(value).rank
    except ValueError:
        return 0


class IncidentService:
    """Deterministic correlation + (M4) lifecycle for incidents."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings
        self._created_incident_ids: set[uuid.UUID] = set()

    # ---- correlation -------------------------------------------------------

    async def correlate_new_events(
        self, *, auto_create: bool | None = None
    ) -> list[Incident]:
        """Correlate every uncorrelated event into incidents. Returns touched incidents.

        Processed oldest-first so the earliest event seeds an incident and later
        related events fold in. Idempotent: an already-correlated event is skipped.
        """
        create = self._settings.incident_auto_create if auto_create is None else auto_create
        events = (
            await self._session.scalars(
                select(SecurityEvent)
                .where(SecurityEvent.status == "new", SecurityEvent.incident_id.is_(None))
                .order_by(SecurityEvent.first_observed_at.asc())
            )
        ).all()
        self._created_incident_ids = set()
        touched: dict[uuid.UUID, Incident] = {}
        for event in events:
            incident = await self._correlate_one(event, create=create)
            if incident is not None:
                touched[incident.id] = incident
        for incident in touched.values():
            await self.recompute_priority(incident.id)
        await self._session.flush()
        # Best-effort notifications for newly created incidents (after priority is set).
        for incident in touched.values():
            if incident.id in self._created_incident_ids:
                await self._notify_new(incident)
        return list(touched.values())

    async def _notify_new(self, incident: Incident) -> None:
        from services.security.notify import notify_incident

        resources = [r.resource_id for r in await self.resources_for(incident.id)]
        await notify_incident(
            self._session, self._settings, incident, "incident_created",
            resource_ids=resources,
        )
        if incident.severity == "critical":
            await notify_incident(
                self._session, self._settings, incident, "incident_critical",
                resource_ids=resources,
            )
        if not incident.owner and incident.priority >= 60:
            await notify_incident(
                self._session, self._settings, incident, "incident_unassigned",
                resource_ids=resources,
            )

    async def recompute_priority(self, incident_id: uuid.UUID) -> Incident:
        """Recompute an incident's deterministic priority + risk rationale.

        Pure, reproducible, and explainable. AI never influences this score.
        """
        incident = await self.get(incident_id)
        events = list(await self.events_for(incident_id))
        resources = list(await self.resources_for(incident_id))
        controls = await self._compensating_controls(incident, resources)
        result = compute_priority(events, resources, compensating_controls=controls)
        incident.priority = result.score
        incident.risk_score = float(result.score)
        incident.risk_rationale = result.rationale
        # Keep severity consistent with the most severe distinct signal.
        incident.severity = result.severity
        await self._session.flush()
        return incident

    async def _compensating_controls(
        self, incident: Incident, resources: list[IncidentResource]
    ) -> int:
        """Count active compliance exceptions covering the incident's resources."""
        if incident.cloud_account_id is None or not resources:
            return 0
        now = _now()
        rows = (
            await self._session.scalars(
                select(ComplianceException).where(
                    ComplianceException.account_id == incident.cloud_account_id
                )
            )
        ).all()
        resource_ids = {r.resource_id for r in resources}
        count = 0
        for exc in rows:
            if not exc.is_active(now):
                continue
            if exc.resource_id is None or exc.resource_id in resource_ids:
                count += 1
        return count

    async def _correlate_one(self, event: SecurityEvent, *, create: bool) -> Incident | None:
        related = await self._related_resource_ids(event)
        tokens = correlation.linkage_tokens(event, related)

        incident = await self._find_matching_incident(event, tokens)
        if incident is None:
            if not create:
                return None
            incident = await self._create_incident(event, tokens)
            matched_token = None
        else:
            matched_token = correlation.shared_token(tokens, incident.linkage_tokens)

        await self._attach_event(incident, event, tokens, matched_token)
        return incident

    async def _find_matching_incident(
        self, event: SecurityEvent, tokens: list[str]
    ) -> Incident | None:
        if not tokens:
            return None
        stmt = select(Incident).where(Incident.status.in_(correlation.OPEN_STATUSES))
        if event.cloud_account_id is not None:
            stmt = stmt.where(Incident.cloud_account_id == event.cloud_account_id)
        else:
            stmt = stmt.where(Incident.account_ref == event.account_ref)
        stmt = stmt.order_by(Incident.last_event_at.desc())
        candidates = (await self._session.scalars(stmt)).all()

        window = self._settings.incident_correlation_window_minutes * 60
        observed = _aware(event.last_observed_at) or _now()
        for incident in candidates:
            if correlation.shared_token(tokens, incident.linkage_tokens) is None:
                continue
            last = _aware(incident.last_event_at)
            if last is not None and abs((observed - last).total_seconds()) > window:
                continue
            return incident
        return None

    async def _create_incident(self, event: SecurityEvent, tokens: list[str]) -> Incident:
        key = correlation.primary_key(tokens, f"event:{event.id}")
        incident = Incident(
            id=uuid.uuid4(),
            title=correlation.incident_title(event),
            description=event.description or event.title,
            severity=event.severity,
            status="new",
            cloud_account_id=event.cloud_account_id,
            account_ref=event.account_ref,
            correlation_key=key,
            linkage_tokens=list(tokens),
            event_count=0,
            first_event_at=_aware(event.first_observed_at),
            last_event_at=_aware(event.last_observed_at),
        )
        self._session.add(incident)
        await self._session.flush()
        self._created_incident_ids.add(incident.id)
        logger.info("incident_created", incident=str(incident.id), key=key)
        return incident

    async def _attach_event(
        self,
        incident: Incident,
        event: SecurityEvent,
        tokens: list[str],
        matched_token: str | None,
    ) -> None:
        # Idempotency: don't double-attach the same event.
        existing = await self._session.scalar(
            select(IncidentEvent).where(
                IncidentEvent.incident_id == incident.id,
                IncidentEvent.event_id == event.id,
            )
        )
        if existing is not None:
            return

        if matched_token is not None:
            signal, rationale = correlation.rationale_for(matched_token)
        else:
            signal, rationale = "seed", "First event in this incident."

        self._session.add(
            IncidentEvent(
                id=uuid.uuid4(),
                incident_id=incident.id,
                event_id=event.id,
                rationale=rationale,
                correlation_signal=signal,
            )
        )
        # Confirmed observation on the timeline (verified vs externally reported
        # is captured in the detail; the occurrence itself is a confirmed fact).
        self._session.add(
            IncidentTimelineEntry(
                id=uuid.uuid4(),
                incident_id=incident.id,
                entry_type="event",
                title=event.title,
                detail={
                    "source": event.source_type,
                    "severity": event.severity,
                    "verified": event.verified,
                    "signal": signal,
                    "rationale": rationale,
                },
                evidence_class="confirmed" if event.verified else "reported",
                occurred_at=_aware(event.first_observed_at) or _now(),
            )
        )
        await self._upsert_resource(incident, event)

        # Update aggregates.
        event.status = "correlated"
        event.incident_id = incident.id
        incident.event_count += 1
        incident.linkage_tokens = list(dict.fromkeys([*incident.linkage_tokens, *tokens]))
        if _sev_rank(event.severity) > _sev_rank(incident.severity):
            incident.severity = event.severity
        first = _aware(incident.first_event_at)
        last = _aware(incident.last_event_at)
        ev_first = _aware(event.first_observed_at)
        ev_last = _aware(event.last_observed_at)
        if ev_first is not None and (first is None or ev_first < first):
            incident.first_event_at = ev_first
        if ev_last is not None and (last is None or ev_last > last):
            incident.last_event_at = ev_last
        if not incident.cloud_account_id and event.cloud_account_id:
            incident.cloud_account_id = event.cloud_account_id
        # Flush so the next event's dedup selects (resource/event uniqueness) and
        # incident matching see this attachment (session uses autoflush=False).
        await self._session.flush()

    async def _upsert_resource(self, incident: Incident, event: SecurityEvent) -> None:
        if not event.resource_id:
            return
        existing = await self._session.scalar(
            select(IncidentResource).where(
                IncidentResource.incident_id == incident.id,
                IncidentResource.resource_id == event.resource_id,
            )
        )
        if existing is not None:
            return
        self._session.add(
            IncidentResource(
                id=uuid.uuid4(),
                incident_id=incident.id,
                resource_id=event.resource_id,
                resource_arn=event.resource_arn,
                region=event.region,
            )
        )

    async def _related_resource_ids(self, event: SecurityEvent) -> list[str]:
        """Resource ids connected to the event's resource in the cloud graph."""
        if event.cloud_account_id is None or not event.resource_id:
            return []
        rows = (
            await self._session.scalars(
                select(CloudRelationship).where(
                    CloudRelationship.account_id == event.cloud_account_id
                )
            )
        ).all()
        related: list[str] = []
        for rel in rows:
            if rel.source_resource_id == event.resource_id:
                related.append(rel.target_resource_id)
            elif rel.target_resource_id == event.resource_id:
                related.append(rel.source_resource_id)
        return related

    # ---- reads -------------------------------------------------------------

    async def get(self, incident_id: uuid.UUID) -> Incident:
        incident = await self._session.get(Incident, incident_id)
        if incident is None:
            raise NotFoundError(f"Incident {incident_id} not found.")
        return incident

    async def list_incidents(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        owner: str | None = None,
        cloud_account_id: uuid.UUID | None = None,
        unassigned: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[Sequence[Incident], int]:
        stmt = select(Incident)
        count_q = select(func.count()).select_from(Incident)
        conds = []
        if status:
            conds.append(Incident.status == status)
        if severity:
            conds.append(Incident.severity == severity)
        if owner:
            conds.append(Incident.owner == owner)
        if cloud_account_id:
            conds.append(Incident.cloud_account_id == cloud_account_id)
        if unassigned:
            conds.append(Incident.owner == "")
        for c in conds:
            stmt = stmt.where(c)
            count_q = count_q.where(c)
        total = int((await self._session.scalar(count_q)) or 0)
        stmt = stmt.order_by(Incident.priority.desc(), Incident.updated_at.desc())
        stmt = stmt.limit(min(max(limit, 1), 500)).offset(max(offset, 0))
        return (await self._session.scalars(stmt)).all(), total

    async def events_for(self, incident_id: uuid.UUID) -> Sequence[SecurityEvent]:
        return (
            await self._session.scalars(
                select(SecurityEvent)
                .where(SecurityEvent.incident_id == incident_id)
                .order_by(SecurityEvent.first_observed_at.asc())
            )
        ).all()

    async def resources_for(self, incident_id: uuid.UUID) -> Sequence[IncidentResource]:
        return (
            await self._session.scalars(
                select(IncidentResource).where(IncidentResource.incident_id == incident_id)
            )
        ).all()

    async def timeline_for(self, incident_id: uuid.UUID) -> Sequence[IncidentTimelineEntry]:
        return (
            await self._session.scalars(
                select(IncidentTimelineEntry)
                .where(IncidentTimelineEntry.incident_id == incident_id)
                .order_by(IncidentTimelineEntry.occurred_at.asc())
            )
        ).all()

    async def notes_for(self, incident_id: uuid.UUID) -> Sequence[IncidentNote]:
        return (
            await self._session.scalars(
                select(IncidentNote)
                .where(IncidentNote.incident_id == incident_id)
                .order_by(IncidentNote.created_at.asc())
            )
        ).all()

    async def build_incident_graph(self, incident_id: uuid.UUID) -> dict:
        """Build the incident's relationship graph (deterministic, evidence-classed).

        Nodes: the incident, its affected resources, involved IAM principals and
        source IPs, and the member events. Edges carry an ``evidence_class``:
        - ``confirmed``  : facts directly reported by an event (event->resource/
          principal/ip) and incident membership;
        - ``inferred``   : resource-to-resource links derived from the cloud graph.
        AI-generated hypotheses are intentionally NOT in this graph; they live in
        the incident's AI investigations and timeline (``evidence_class`` hypothesis).
        """
        incident = await self.get(incident_id)
        events = await self.events_for(incident_id)
        resources = await self.resources_for(incident_id)

        nodes: list[dict] = [
            {
                "id": f"incident:{incident.id}",
                "type": "incident",
                "label": incident.title,
                "severity": incident.severity,
                "status": incident.status,
            }
        ]
        edges: list[dict] = []
        seen_nodes = {nodes[0]["id"]}

        def _add_node(node: dict) -> None:
            if node["id"] not in seen_nodes:
                nodes.append(node)
                seen_nodes.add(node["id"])

        resource_ids = {r.resource_id for r in resources}
        for res in resources:
            nid = f"resource:{res.resource_id}"
            _add_node({
                "id": nid, "type": "resource", "label": res.resource_id,
                "service": res.service, "region": res.region, "exposure": res.exposure,
            })
            edges.append({
                "source": f"incident:{incident.id}", "target": nid,
                "relation": "involves", "evidence_class": "confirmed", "detail": {},
            })

        for ev in events:
            ev_node = f"event:{ev.id}"
            _add_node({
                "id": ev_node, "type": "event", "label": ev.title,
                "source_type": ev.source_type, "severity": ev.severity,
                "verified": ev.verified,
            })
            if ev.resource_id and ev.resource_id in resource_ids:
                edges.append({
                    "source": ev_node, "target": f"resource:{ev.resource_id}",
                    "relation": "affects", "evidence_class": "confirmed", "detail": {},
                })
            if ev.principal:
                pid = f"principal:{ev.principal}"
                _add_node({"id": pid, "type": "principal", "label": ev.principal})
                edges.append({
                    "source": pid, "target": ev_node,
                    "relation": "performed", "evidence_class": "confirmed", "detail": {},
                })
            if ev.source_ip:
                ipid = f"ip:{ev.source_ip}"
                _add_node({"id": ipid, "type": "ip", "label": ev.source_ip})
                edges.append({
                    "source": ipid, "target": ev_node,
                    "relation": "origin", "evidence_class": "confirmed", "detail": {},
                })

        # Inferred: resource-to-resource links from the cloud relationship graph.
        if incident.cloud_account_id is not None and resource_ids:
            rels = (
                await self._session.scalars(
                    select(CloudRelationship).where(
                        CloudRelationship.account_id == incident.cloud_account_id
                    )
                )
            ).all()
            for rel in rels:
                linked = (
                    rel.source_resource_id in resource_ids
                    and rel.target_resource_id in resource_ids
                )
                if linked:
                    edges.append({
                        "source": f"resource:{rel.source_resource_id}",
                        "target": f"resource:{rel.target_resource_id}",
                        "relation": rel.relation,
                        "evidence_class": "inferred",
                        "detail": dict(rel.detail or {}),
                    })

        return {
            "incident_id": str(incident.id),
            "nodes": nodes,
            "edges": edges,
            "legend": {
                "confirmed": "Fact reported directly by a security event or membership.",
                "inferred": "Relationship derived deterministically from the cloud graph.",
                "hypothesis": "AI hypotheses are not in this graph; see AI investigations.",
            },
        }

    async def rationale_for_events(self, incident_id: uuid.UUID) -> dict[str, dict[str, str]]:
        """Map event_id -> {rationale, signal} for the incident's links."""
        links = (
            await self._session.scalars(
                select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)
            )
        ).all()
        return {
            str(le.event_id): {"rationale": le.rationale, "signal": le.correlation_signal}
            for le in links
        }

    # ---- lifecycle ---------------------------------------------------------

    async def create_manual(
        self, *, event_ids: list[uuid.UUID], title: str = "", description: str = ""
    ) -> Incident:
        """Create an incident explicitly from one or more existing events."""
        if not event_ids:
            raise ValidationError("At least one event id is required.")
        events = (
            await self._session.scalars(
                select(SecurityEvent).where(SecurityEvent.id.in_(event_ids))
            )
        ).all()
        if not events:
            raise NotFoundError("None of the given events were found.")
        seed = events[0]
        tokens = correlation.linkage_tokens(seed, await self._related_resource_ids(seed))
        incident = await self._create_incident(seed, tokens)
        if title:
            incident.title = title[:500]
        if description:
            incident.description = description
        for event in events:
            if event.incident_id is not None:
                continue
            ev_tokens = correlation.linkage_tokens(
                event, await self._related_resource_ids(event)
            )
            await self._attach_event(incident, event, ev_tokens, None)
        await self.recompute_priority(incident.id)
        return incident

    async def update(
        self,
        incident_id: uuid.UUID,
        *,
        owner: str | None = None,
        root_cause_hypothesis: str | None = None,
        resolution_summary: str | None = None,
    ) -> Incident:
        incident = await self.get(incident_id)
        if owner is not None:
            incident.owner = owner[:255]
        if root_cause_hypothesis is not None:
            incident.root_cause_hypothesis = root_cause_hypothesis
        if resolution_summary is not None:
            incident.resolution_summary = resolution_summary
        await self._session.flush()
        return incident

    async def transition(
        self, incident_id: uuid.UUID, new_status: str, *, actor: str = "", note: str = ""
    ) -> Incident:
        incident = await self.get(incident_id)
        try:
            target = IncidentStatus(new_status)
        except ValueError as exc:
            raise ValidationError(f"Unknown incident status '{new_status}'.") from exc

        current = incident.status
        allowed = _TRANSITIONS.get(current, set())
        if target.value != current and target not in allowed:
            raise ConflictError(
                f"Cannot transition incident from '{current}' to '{target.value}'. "
                f"Allowed: {sorted(s.value for s in allowed) or 'none'}."
            )

        now = _now()
        incident.status = target.value
        if incident.acknowledged_at is None and current == IncidentStatus.NEW.value:
            incident.acknowledged_at = now
        if target in _TERMINAL:
            incident.resolved_at = now

        self._session.add(
            IncidentTimelineEntry(
                id=uuid.uuid4(),
                incident_id=incident.id,
                entry_type="status_change",
                title=f"Status changed to {target.value}",
                detail={"from": current, "to": target.value, "note": note[:500]},
                evidence_class="action",
                actor=actor[:255],
                occurred_at=now,
            )
        )
        await self._session.flush()
        if target == IncidentStatus.RESOLVED:
            from services.security.notify import notify_incident

            resources = [r.resource_id for r in await self.resources_for(incident.id)]
            await notify_incident(
                self._session, self._settings, incident, "incident_resolved",
                resource_ids=resources,
            )
        logger.info("incident_transition", incident=str(incident.id), to=target.value)
        return incident

    async def add_note(
        self, incident_id: uuid.UUID, *, body: str, author: str = ""
    ) -> IncidentNote:
        await self.get(incident_id)
        if not body.strip():
            raise ValidationError("A note body is required.")
        note = IncidentNote(
            id=uuid.uuid4(),
            incident_id=incident_id,
            author=author[:255],
            body=neutralize(body, max_length=4000),
        )
        self._session.add(note)
        await self._session.flush()
        return note
