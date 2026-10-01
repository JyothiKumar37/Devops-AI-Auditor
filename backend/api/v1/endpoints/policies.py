"""Policy-as-code management endpoints (CRUD, versions, assign, evaluate)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response, status
from sqlalchemy import select

from api.dependencies import DbSessionDep
from core.exceptions import ValidationError
from models.finding import Finding
from models.scan import RepositoryFile
from models.schemas import (
    PolicyAssignRequest,
    PolicyCreateRequest,
    PolicyEvaluateRequest,
    PolicyEvaluationResult,
    PolicyListResponse,
    PolicyRead,
    PolicyUpdateRequest,
    PolicyVersionRead,
)
from services.policy_service import PolicyService
from services.risk import RiskInput, assess_risk

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("", response_model=PolicyListResponse, summary="List policies")
async def list_policies(session: DbSessionDep) -> PolicyListResponse:
    items = await PolicyService(session).list_policies()
    return PolicyListResponse(
        total=len(items), items=[PolicyRead.model_validate(p) for p in items]
    )


@router.post(
    "", response_model=PolicyRead, status_code=status.HTTP_201_CREATED,
    summary="Create a policy (validates the YAML)",
)
async def create_policy(body: PolicyCreateRequest, session: DbSessionDep) -> PolicyRead:
    policy = await PolicyService(session).create(body.name, body.yaml_text, body.description)
    return PolicyRead.model_validate(policy)


@router.get("/{policy_id}", response_model=PolicyRead, summary="Get a policy")
async def get_policy(policy_id: uuid.UUID, session: DbSessionDep) -> PolicyRead:
    return PolicyRead.model_validate(await PolicyService(session).get(policy_id))


@router.put("/{policy_id}", response_model=PolicyRead, summary="Update a policy")
async def update_policy(
    policy_id: uuid.UUID, body: PolicyUpdateRequest, session: DbSessionDep
) -> PolicyRead:
    policy = await PolicyService(session).update(
        policy_id,
        yaml_text=body.yaml_text,
        description=body.description,
        enabled=body.enabled,
    )
    return PolicyRead.model_validate(policy)


@router.delete(
    "/{policy_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a policy"
)
async def delete_policy(policy_id: uuid.UUID, session: DbSessionDep) -> Response:
    await PolicyService(session).delete(policy_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{policy_id}/versions",
    response_model=list[PolicyVersionRead],
    summary="List a policy's version history",
)
async def policy_versions(
    policy_id: uuid.UUID, session: DbSessionDep
) -> list[PolicyVersionRead]:
    versions = await PolicyService(session).versions(policy_id)
    return [PolicyVersionRead.model_validate(v) for v in versions]


@router.post(
    "/{policy_id}/assign",
    response_model=PolicyRead,
    summary="Assign a policy to a repository or the whole workspace",
)
async def assign_policy(
    policy_id: uuid.UUID, body: PolicyAssignRequest, session: DbSessionDep
) -> PolicyRead:
    service = PolicyService(session)
    await service.assign(policy_id, body.scope_type, body.scope_value, body.environment)
    return PolicyRead.model_validate(await service.get(policy_id))


@router.post(
    "/{policy_id}/evaluate",
    response_model=PolicyEvaluationResult,
    summary="Evaluate a policy against a scan's findings or an inline list",
)
async def evaluate_policy(
    policy_id: uuid.UUID, body: PolicyEvaluateRequest, session: DbSessionDep
) -> PolicyEvaluationResult:
    service = PolicyService(session)
    policy = await service.get(policy_id)
    if body.findings is not None:
        findings = body.findings
    elif body.scan_id is not None:
        findings = await _scan_findings(session, body.scan_id)
    else:
        raise ValidationError("Provide either 'scan_id' or 'findings' to evaluate.")
    result = await service.evaluate_and_store(
        policy, findings, subject_type="adhoc",
        subject_id=str(body.scan_id or "inline"), environment=body.environment,
    )
    return PolicyEvaluationResult(
        status=result.status,
        rules=[
            {"id": r.id, "action": r.action, "matched": r.matched, "passed": r.passed}
            for r in result.rules
        ],
        violations=result.violations,
    )


async def _scan_findings(session: DbSessionDep, scan_id: uuid.UUID) -> list[dict]:
    """Build policy-evaluation dicts (with risk score) from a scan's findings."""
    findings = list(
        (await session.scalars(select(Finding).where(Finding.scan_id == scan_id))).all()
    )
    path_rows = (
        await session.execute(
            select(RepositoryFile.id, RepositoryFile.path).where(
                RepositoryFile.scan_id == scan_id
            )
        )
    ).all()
    path_by_id = {row[0]: row[1] for row in path_rows}
    out: list[dict] = []
    for f in findings:
        path = path_by_id.get(f.file_id)
        risk = assess_risk(
            RiskInput(
                rule_id=f.rule_id, scanner=f.scanner, category=str(f.category),
                severity=str(f.severity), confidence=str(f.confidence),
                title=f.title, description=f.description or "", evidence=f.evidence,
                file_path=path,
            )
        ).score
        out.append(
            {
                "rule_id": f.rule_id, "scanner": f.scanner, "category": str(f.category),
                "severity": str(f.severity), "confidence": str(f.confidence),
                "file": path, "risk_score": risk, "is_new": False,
            }
        )
    return out
