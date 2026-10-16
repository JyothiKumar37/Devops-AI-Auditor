"""M8 tests: containment plan generation, approval workflow, gated execution.

Verifies: deterministic plan generation (non-destructive), approval required
before execution, write actions gated by cloud_write_enabled (never auto-mutate),
duplicate execution prevented, and advisory plans recorded honestly as skipped.
"""

from __future__ import annotations

import uuid

import pytest

from core.config import Settings
from core.exceptions import ConflictError, ValidationError
from models.security import SecurityEvent
from services.containment_service import ContainmentService
from services.incident_service import IncidentService


def _event(**kw) -> SecurityEvent:
    base = dict(
        id=uuid.uuid4(), source_type="cloud_scan", source_event_id=str(uuid.uuid4()),
        category="exposure", event_type="AWS-S3-001", severity="critical",
        confidence="high", title="Public bucket", fingerprint=uuid.uuid4().hex,
        status="new", verified=True, related_finding_ids=[str(uuid.uuid4())],
    )
    base.update(kw)
    return SecurityEvent(**base)


async def _incident_with(sm, settings, **event_kw) -> uuid.UUID:
    event_kw.setdefault("resource_id", "bucket-x")
    async with sm() as session:
        session.add(_event(account_ref="acct", **event_kw))
        await session.commit()
        incidents = await IncidentService(session, settings).correlate_new_events()
        await session.commit()
        return incidents[0].id


async def test_generate_plans_is_deterministic_and_idempotent(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _incident_with(sm, settings)
    async with sm() as session:
        svc = ContainmentService(session, settings)
        first = await svc.generate_plans(inc_id)
        await session.commit()
        assert len(first) == 1
        plan = first[0]
        assert plan.status == "proposed"
        assert plan.capability == "write"  # exposure -> SG/policy tighten (write-class)
        assert plan.rollback_plan and plan.verification_steps
        # Re-generating does not duplicate.
        again = await svc.generate_plans(inc_id)
        await session.commit()
        assert len(again) == 0


async def test_execute_requires_approval(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _incident_with(sm, settings)
    async with sm() as session:
        svc = ContainmentService(session, settings)
        plan = (await svc.generate_plans(inc_id))[0]
        await session.commit()
        with pytest.raises(ConflictError):
            await svc.execute(plan.id, actor="alice")


async def test_approve_requires_approver_identity(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _incident_with(sm, settings)
    async with sm() as session:
        svc = ContainmentService(session, settings)
        plan = (await svc.generate_plans(inc_id))[0]
        await session.commit()
        with pytest.raises(ValidationError):
            await svc.approve(plan.id, approver="")


async def test_write_execution_gated_when_disabled(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _incident_with(sm, settings)
    async with sm() as session:
        svc = ContainmentService(session, settings)
        plan = (await svc.generate_plans(inc_id))[0]
        await session.commit()
        await svc.approve(plan.id, approver="alice", reason="ok")
        await session.commit()
        execution = await svc.execute(plan.id, actor="alice")
        await session.commit()
        # cloud_write_enabled defaults False -> never mutates.
        assert execution.status == "not_enabled"
        assert execution.after_state == {}


async def test_duplicate_execution_prevented(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _incident_with(sm, settings)
    async with sm() as session:
        svc = ContainmentService(session, settings)
        plan = (await svc.generate_plans(inc_id))[0]
        await session.commit()
        await svc.approve(plan.id, approver="alice")
        await session.commit()
        await svc.execute(plan.id, actor="alice")
        await session.commit()
        with pytest.raises(ConflictError):
            await svc.execute(plan.id, actor="alice")


async def test_advisory_plan_recorded_as_skipped(mem_db) -> None:
    sm, settings = mem_db
    # An identity (PLAN-capability) incident.
    inc_id = await _incident_with(
        sm, settings, category="identity", event_type="AWS-IAM-002",
        title="Wildcard trust", principal="role/admin", resource_id="role/admin",
    )
    async with sm() as session:
        svc = ContainmentService(session, settings)
        plan = (await svc.generate_plans(inc_id))[0]
        await session.commit()
        assert plan.capability == "plan"
        await svc.approve(plan.id, approver="alice")
        await session.commit()
        execution = await svc.execute(plan.id, actor="alice")
        await session.commit()
        assert execution.status == "skipped"


async def test_write_execution_still_not_mutated_when_enabled(mem_db) -> None:
    sm, _settings = mem_db
    # Even with cloud_write_enabled, the read-only connector performs no mutation.
    settings = Settings(
        environment="development", llm_provider="none",
        integration_encryption_key=_settings.integration_encryption_key,
        cloud_write_enabled=True,
    )
    inc_id = await _incident_with(sm, settings)
    async with sm() as session:
        svc = ContainmentService(session, settings)
        plan = (await svc.generate_plans(inc_id))[0]
        await session.commit()
        await svc.approve(plan.id, approver="alice")
        await session.commit()
        execution = await svc.execute(plan.id, actor="alice")
        await session.commit()
        assert execution.status == "not_enabled"
        assert "read-only" in execution.output.lower()
