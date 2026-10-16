"""Containment / remediation plan operations (Phase 5).

Plans are generated + listed under ``/incidents/{id}/remediation-plans``; the
per-plan decisions (approve/reject) and gated execution live here under
``/remediation-plans/{plan_id}``. Execution never mutates infrastructure in this
read-only build - it records the intended action + current state honestly.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter

from api.dependencies import ContainmentServiceDep
from models.schemas import (
    ContainmentApprovalRead,
    ContainmentDecisionRequest,
    ContainmentExecuteRequest,
    ContainmentExecutionRead,
    ContainmentPlanDetail,
    ContainmentPlanRead,
)

router = APIRouter(prefix="/remediation-plans", tags=["containment"])


async def _detail(service: ContainmentServiceDep, plan_id: uuid.UUID) -> ContainmentPlanDetail:
    plan = await service.get_plan(plan_id)
    detail = ContainmentPlanDetail.model_validate(plan)
    detail.approvals = [
        ContainmentApprovalRead.model_validate(a) for a in await service.approvals_for(plan_id)
    ]
    detail.executions = [
        ContainmentExecutionRead.model_validate(e)
        for e in await service.executions_for(plan_id)
    ]
    return detail


@router.get(
    "/{plan_id}", response_model=ContainmentPlanDetail, summary="Get a containment plan"
)
async def get_plan(plan_id: uuid.UUID, service: ContainmentServiceDep) -> ContainmentPlanDetail:
    return await _detail(service, plan_id)


@router.post(
    "/{plan_id}/approve",
    response_model=ContainmentPlanRead,
    summary="Approve a containment plan (authorized)",
)
async def approve_plan(
    plan_id: uuid.UUID, body: ContainmentDecisionRequest, service: ContainmentServiceDep
) -> ContainmentPlanRead:
    plan = await service.approve(plan_id, approver=body.approver, reason=body.reason)
    return ContainmentPlanRead.model_validate(plan)


@router.post(
    "/{plan_id}/reject",
    response_model=ContainmentPlanRead,
    summary="Reject a containment plan",
)
async def reject_plan(
    plan_id: uuid.UUID, body: ContainmentDecisionRequest, service: ContainmentServiceDep
) -> ContainmentPlanRead:
    plan = await service.reject(plan_id, approver=body.approver, reason=body.reason)
    return ContainmentPlanRead.model_validate(plan)


@router.post(
    "/{plan_id}/execute",
    response_model=ContainmentExecutionRead,
    summary="Execute an approved plan (gated by cloud_write_enabled; never auto-mutates)",
)
async def execute_plan(
    plan_id: uuid.UUID, body: ContainmentExecuteRequest, service: ContainmentServiceDep
) -> ContainmentExecutionRead:
    execution = await service.execute(plan_id, actor=body.actor)
    return ContainmentExecutionRead.model_validate(execution)


@router.post(
    "/{plan_id}/verify",
    response_model=ContainmentExecutionRead,
    summary="Independently verify a plan by re-running deterministic checks",
)
async def verify_plan(
    plan_id: uuid.UUID, service: ContainmentServiceDep
) -> ContainmentExecutionRead:
    execution = await service.verify(plan_id)
    return ContainmentExecutionRead.model_validate(execution)
