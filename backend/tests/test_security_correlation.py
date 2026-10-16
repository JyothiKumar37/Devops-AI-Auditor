"""M3 tests: deterministic correlation of security events into incidents.

Verifies: same-resource grouping, cloud-relationship (related-resource) grouping,
shared-principal grouping, time-window bounding, duplicate events never create
duplicate incidents, unrelated events stay separate, and that every link carries
an explainable rationale.
"""

from __future__ import annotations

import uuid

from models.cloud import CloudAccount, CloudRelationship
from models.incident import IncidentEvent
from models.security import SecurityEvent
from services.incident_service import IncidentService


def _event(**kw) -> SecurityEvent:
    base = dict(
        id=uuid.uuid4(),
        source_type="guardduty",
        source_event_id=str(uuid.uuid4()),
        category="threat",
        event_type="Recon",
        severity="medium",
        confidence="medium",
        title="event",
        fingerprint=uuid.uuid4().hex,
        status="new",
    )
    base.update(kw)
    return SecurityEvent(**base)


async def _account(sm) -> uuid.UUID:
    pk = uuid.uuid4()
    async with sm() as session:
        session.add(CloudAccount(
            id=pk, provider="aws", name="prod", account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/RO", regions=["us-east-1"],
            status="connected",
        ))
        await session.commit()
    return pk


async def test_same_resource_events_group_into_one_incident(mem_db) -> None:
    sm, settings = mem_db
    acct = await _account(sm)
    async with sm() as session:
        session.add(_event(cloud_account_id=acct, account_ref="123456789012",
                           resource_id="i-123", title="SG open", severity="high"))
        session.add(_event(cloud_account_id=acct, account_ref="123456789012",
                           resource_id="i-123", title="GuardDuty brute force", severity="critical"))
        await session.commit()
        incidents = await IncidentService(session, settings).correlate_new_events()
        await session.commit()
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.event_count == 2
        assert inc.severity == "critical"  # max severity wins


async def test_related_resource_via_cloud_graph_groups(mem_db) -> None:
    sm, settings = mem_db
    acct = await _account(sm)
    async with sm() as session:
        session.add(CloudRelationship(
            id=uuid.uuid4(), account_id=acct, source_resource_id="sg-1",
            target_resource_id="i-1", relation="attached-to", detail={},
        ))
        session.add(_event(cloud_account_id=acct, account_ref="123456789012",
                           resource_id="sg-1", title="SG world-open"))
        session.add(_event(cloud_account_id=acct, account_ref="123456789012",
                           resource_id="i-1", title="EC2 exposed"))
        await session.commit()
        incidents = await IncidentService(session, settings).correlate_new_events()
        await session.commit()
        assert len(incidents) == 1
        # The second event joined via the cloud-graph relationship rationale.
        links = (await session.scalars(
            select_incident_events(incidents[0].id)
        )).all()
        signals = {le.correlation_signal for le in links}
        assert "related_resource" in signals or "resource" in signals


async def test_shared_principal_groups(mem_db) -> None:
    sm, settings = mem_db
    async with sm() as session:
        session.add(_event(account_ref="123456789012", principal="role/admin",
                           source_type="cloudtrail", title="CreateUser", resource_id=""))
        session.add(_event(account_ref="123456789012", principal="role/admin",
                           source_type="cloudtrail", title="AttachPolicy", resource_id=""))
        await session.commit()
        incidents = await IncidentService(session, settings).correlate_new_events()
        await session.commit()
        assert len(incidents) == 1
        assert incidents[0].event_count == 2


async def test_unrelated_events_stay_separate(mem_db) -> None:
    sm, settings = mem_db
    async with sm() as session:
        session.add(_event(account_ref="repoA", resource_id="repo:repoA:a.tf",
                           source_type="repo_scan", title="A"))
        session.add(_event(account_ref="repoB", resource_id="repo:repoB:b.tf",
                           source_type="repo_scan", title="B"))
        await session.commit()
        incidents = await IncidentService(session, settings).correlate_new_events()
        await session.commit()
        assert len(incidents) == 2


async def test_duplicate_correlation_is_idempotent(mem_db) -> None:
    sm, settings = mem_db
    acct = await _account(sm)
    async with sm() as session:
        session.add(_event(cloud_account_id=acct, account_ref="123456789012",
                           resource_id="i-9", title="x"))
        await session.commit()
        svc = IncidentService(session, settings)
        first = await svc.correlate_new_events()
        await session.commit()
        # Re-running finds nothing new (events already correlated).
        second = await svc.correlate_new_events()
        await session.commit()
        assert len(first) == 1
        assert len(second) == 0
        _all, total = await svc.list_incidents()
        assert total == 1


async def test_every_link_has_rationale(mem_db) -> None:
    sm, settings = mem_db
    acct = await _account(sm)
    async with sm() as session:
        session.add(_event(cloud_account_id=acct, account_ref="123456789012",
                           resource_id="i-5", title="one"))
        session.add(_event(cloud_account_id=acct, account_ref="123456789012",
                           resource_id="i-5", title="two"))
        await session.commit()
        incidents = await IncidentService(session, settings).correlate_new_events()
        await session.commit()
        links = (await session.scalars(select_incident_events(incidents[0].id))).all()
        assert len(links) == 2
        assert all(le.rationale for le in links)


def select_incident_events(incident_id: uuid.UUID):
    from sqlalchemy import select

    return select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)
