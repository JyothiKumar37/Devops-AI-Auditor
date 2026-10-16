"""M4 tests: incident lifecycle, manual creation, notes, timeline, filtering.

Service-level tests on the shared in-memory DB. Validated status transitions are
enforced on the backend (ConflictError on illegal moves). HTTP endpoint smoke
tests live in M12.
"""

from __future__ import annotations

import uuid

import pytest

from core.exceptions import ConflictError, ValidationError
from models.security import SecurityEvent
from services.incident_service import IncidentService


def _event(**kw) -> SecurityEvent:
    base = dict(
        id=uuid.uuid4(), source_type="guardduty", source_event_id=str(uuid.uuid4()),
        category="threat", event_type="Recon", severity="high", confidence="medium",
        title="event", fingerprint=uuid.uuid4().hex, status="new",
    )
    base.update(kw)
    return SecurityEvent(**base)


async def _seed_incident(sm, settings, **event_kw):
    async with sm() as session:
        session.add(_event(account_ref="acct", resource_id="i-1", **event_kw))
        await session.commit()
        svc = IncidentService(session, settings)
        incidents = await svc.correlate_new_events()
        await session.commit()
        return incidents[0].id


async def test_valid_transition_path(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _seed_incident(sm, settings)
    async with sm() as session:
        svc = IncidentService(session, settings)
        for target in ["triaging", "investigating", "containment_planned",
                       "containment_approved", "contained", "resolved"]:
            incident = await svc.transition(inc_id, target, actor="alice")
            await session.commit()
            assert incident.status == target
        assert incident.resolved_at is not None
        assert incident.acknowledged_at is not None


async def test_illegal_transition_rejected(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _seed_incident(sm, settings)
    async with sm() as session:
        svc = IncidentService(session, settings)
        # NEW -> CONTAINED is not allowed (must go through investigation/planning).
        with pytest.raises(ConflictError):
            await svc.transition(inc_id, "contained")


async def test_unknown_status_rejected(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _seed_incident(sm, settings)
    async with sm() as session:
        svc = IncidentService(session, settings)
        with pytest.raises(ValidationError):
            await svc.transition(inc_id, "banana")


async def test_transition_records_timeline_action(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _seed_incident(sm, settings)
    async with sm() as session:
        svc = IncidentService(session, settings)
        await svc.transition(inc_id, "triaging", actor="bob", note="looking")
        await session.commit()
        timeline = await svc.timeline_for(inc_id)
        actions = [t for t in timeline if t.entry_type == "status_change"]
        assert len(actions) == 1
        assert actions[0].evidence_class == "action"
        assert actions[0].actor == "bob"


async def test_false_positive_is_terminal_but_reopenable(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _seed_incident(sm, settings)
    async with sm() as session:
        svc = IncidentService(session, settings)
        await svc.transition(inc_id, "false_positive")
        await session.commit()
        # Reopen is allowed back to investigating.
        incident = await svc.transition(inc_id, "investigating")
        await session.commit()
        assert incident.status == "investigating"


async def test_manual_create_and_notes(mem_db) -> None:
    sm, settings = mem_db
    async with sm() as session:
        ev = _event(account_ref="acct", resource_id="bucket-x", title="public bucket")
        session.add(ev)
        await session.commit()
        ev_id = ev.id
    async with sm() as session:
        svc = IncidentService(session, settings)
        incident = await svc.create_manual(event_ids=[ev_id], title="Manual incident")
        await session.commit()
        assert incident.title == "Manual incident"
        assert incident.event_count == 1
        note = await svc.add_note(incident.id, body="investigating now", author="carol")
        await session.commit()
        assert note.author == "carol"
        notes = await svc.notes_for(incident.id)
        assert len(notes) == 1


async def test_update_owner_and_root_cause(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _seed_incident(sm, settings)
    async with sm() as session:
        svc = IncidentService(session, settings)
        incident = await svc.update(inc_id, owner="team-sec", root_cause_hypothesis="open SG")
        await session.commit()
        assert incident.owner == "team-sec"
        assert incident.root_cause_hypothesis == "open SG"


async def test_list_filters_by_status_and_unassigned(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _seed_incident(sm, settings)
    async with sm() as session:
        svc = IncidentService(session, settings)
        items, total = await svc.list_incidents(unassigned=True)
        assert total == 1
        await svc.update(inc_id, owner="someone")
        await session.commit()
        items, total = await svc.list_incidents(unassigned=True)
        assert total == 0
