"""M9 tests: containment verification by re-running deterministic cloud rules.

A successful execution never means "fixed" - only a deterministic re-check does.
Covers unresolved -> fixed transition after remediating the asset, inconclusive
when there's nothing deterministic to check, and verify-before-execute guard.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from core.exceptions import ConflictError
from models.cloud import CloudAccount, CloudAsset
from models.security import SecurityEvent
from services.containment_service import ContainmentService
from services.incident_service import IncidentService

_BLOCKED = {
    "BlockPublicAcls": True, "IgnorePublicAcls": True,
    "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
}


def _event(**kw) -> SecurityEvent:
    base = dict(
        id=uuid.uuid4(), source_type="cloud_scan", source_event_id=str(uuid.uuid4()),
        category="exposure", event_type="AWS-S3-001", severity="high",
        confidence="high", title="Public bucket", fingerprint=uuid.uuid4().hex,
        status="new", verified=True,
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


async def _bucket(sm, account_id, *, public: bool) -> None:
    attrs = {"policy_status_public": True} if public else {
        "public_access_block": _BLOCKED, "encryption": True,
    }
    async with sm() as session:
        session.add(CloudAsset(
            id=uuid.uuid4(), account_id=account_id, service="s3",
            resource_type="bucket", resource_id="bucket-x", region="us-east-1",
            exposure="public" if public else "private", tags={}, attributes=attrs,
        ))
        await session.commit()


async def _approved_executed_plan(sm, settings, account_id):
    async with sm() as session:
        session.add(_event(cloud_account_id=account_id, account_ref="123456789012",
                           resource_id="bucket-x"))
        await session.commit()
        inc = (await IncidentService(session, settings).correlate_new_events())[0]
        await session.commit()
        svc = ContainmentService(session, settings)
        plan = (await svc.generate_plans(inc.id))[0]
        await session.commit()
        await svc.approve(plan.id, approver="alice")
        await session.commit()
        await svc.execute(plan.id, actor="alice")
        await session.commit()
        return plan.id


async def test_verify_unresolved_then_fixed(mem_db) -> None:
    sm, settings = mem_db
    acct = await _account(sm)
    await _bucket(sm, acct, public=True)
    plan_id = await _approved_executed_plan(sm, settings, acct)

    async with sm() as session:
        svc = ContainmentService(session, settings)
        execution = await svc.verify(plan_id)
        await session.commit()
        assert execution.verification["status"] == "unresolved"

    # Remediate the asset (as a human would), then re-verify -> fixed.
    async with sm() as session:
        asset = await session.scalar(
            select(CloudAsset).where(CloudAsset.resource_id == "bucket-x")
        )
        asset.exposure = "private"
        asset.attributes = {"public_access_block": _BLOCKED, "encryption": True}
        await session.commit()

    async with sm() as session:
        svc = ContainmentService(session, settings)
        execution = await svc.verify(plan_id)
        await session.commit()
        assert execution.verification["status"] == "fixed"
        plan = await svc.get_plan(plan_id)
        assert plan.status == "verified"


async def test_verify_requires_execution_first(mem_db) -> None:
    sm, settings = mem_db
    acct = await _account(sm)
    await _bucket(sm, acct, public=True)
    async with sm() as session:
        session.add(_event(cloud_account_id=acct, account_ref="123456789012",
                           resource_id="bucket-x"))
        await session.commit()
        inc = (await IncidentService(session, settings).correlate_new_events())[0]
        await session.commit()
        svc = ContainmentService(session, settings)
        plan = (await svc.generate_plans(inc.id))[0]
        await session.commit()
        with pytest.raises(ConflictError):
            await svc.verify(plan.id)


async def test_verify_inconclusive_without_cloud_rule(mem_db) -> None:
    sm, settings = mem_db
    acct = await _account(sm)
    async with sm() as session:
        # A threat event (GuardDuty) has no deterministic cloud rule to re-check.
        session.add(_event(cloud_account_id=acct, account_ref="123456789012",
                           resource_id="i-1", source_type="guardduty",
                           category="threat", event_type="Recon:EC2/PortProbe",
                           verified=False))
        await session.commit()
        inc = (await IncidentService(session, settings).correlate_new_events())[0]
        await session.commit()
        svc = ContainmentService(session, settings)
        plan = (await svc.generate_plans(inc.id))[0]
        await session.commit()
        await svc.approve(plan.id, approver="alice")
        await session.commit()
        await svc.execute(plan.id, actor="alice")
        await session.commit()
        execution = await svc.verify(plan.id)
        await session.commit()
        assert execution.verification["status"] == "inconclusive"
