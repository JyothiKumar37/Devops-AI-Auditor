"""M6 tests: incident relationship graph (confirmed facts vs inferred links)."""

from __future__ import annotations

import uuid

from models.cloud import CloudAccount, CloudRelationship
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


async def test_graph_has_confirmed_and_inferred_edges(mem_db) -> None:
    sm, settings = mem_db
    acct = await _account(sm)
    async with sm() as session:
        session.add(CloudRelationship(
            id=uuid.uuid4(), account_id=acct, source_resource_id="sg-1",
            target_resource_id="i-1", relation="attached-to", detail={},
        ))
        session.add(_event(cloud_account_id=acct, account_ref="123456789012",
                           resource_id="sg-1", principal="role/admin", source_ip="9.9.9.9",
                           title="SG open"))
        session.add(_event(cloud_account_id=acct, account_ref="123456789012",
                           resource_id="i-1", title="EC2 compromised", severity="critical"))
        await session.commit()
        svc = IncidentService(session, settings)
        incidents = await svc.correlate_new_events()
        await session.commit()
        graph = await svc.build_incident_graph(incidents[0].id)

        node_types = {n["type"] for n in graph["nodes"]}
        assert {"incident", "resource", "event", "principal", "ip"} <= node_types

        classes = {e["evidence_class"] for e in graph["edges"]}
        assert "confirmed" in classes
        assert "inferred" in classes  # sg-1 <-> i-1 from the cloud graph

        # Confirmed edges include event->resource "affects".
        affects = [e for e in graph["edges"] if e["relation"] == "affects"]
        assert affects and all(e["evidence_class"] == "confirmed" for e in affects)
        # Inferred edge connects the two resources.
        inferred = [e for e in graph["edges"] if e["evidence_class"] == "inferred"]
        assert any("resource:sg-1" in (e["source"], e["target"]) for e in inferred)


async def test_graph_legend_notes_hypotheses_excluded(mem_db) -> None:
    sm, settings = mem_db
    async with sm() as session:
        session.add(_event(account_ref="repoA", resource_id="repo:repoA:a.tf",
                           source_type="repo_scan", verified=True, title="finding"))
        await session.commit()
        svc = IncidentService(session, settings)
        incidents = await svc.correlate_new_events()
        await session.commit()
        graph = await svc.build_incident_graph(incidents[0].id)
        assert "hypothesis" in graph["legend"]
        # No inferred/hypothesis edges for a single repo event (only confirmed).
        assert all(e["evidence_class"] == "confirmed" for e in graph["edges"])
