"""AI investigation endpoints (Phase 3).

Natural-language investigation over deterministic scan data, answered through
the controlled read-only tool layer. Results are evidence-grounded and clearly
labeled as AI analysis - never authoritative findings. Works with AI disabled
(returns a deterministic, tool-only fallback).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter

from api.dependencies import (
    AiPrReviewServiceDep,
    AiSecurityReviewServiceDep,
    InvestigationServiceDep,
    RemediationPlanServiceDep,
)
from models.schemas import (
    AIReviewResponse,
    InvestigationDetail,
    InvestigationListResponse,
    InvestigationRequest,
    InvestigationResponse,
    InvestigationSummary,
    RemediationPlanRequest,
    RemediationPlanResponse,
    RepositoryInvestigationRequest,
)

router = APIRouter(prefix="/ai", tags=["ai-investigation"])


@router.get(
    "/investigations",
    response_model=InvestigationListResponse,
    summary="List past AI investigation sessions",
)
async def list_investigations(
    service: InvestigationServiceDep,
    scan_id: uuid.UUID | None = None,
    repository: str | None = None,
    limit: int = 50,
) -> InvestigationListResponse:
    rows = await service.list_investigations(
        scan_id=scan_id, repository=repository, limit=limit
    )
    return InvestigationListResponse(
        total=len(rows), items=[InvestigationSummary.model_validate(r) for r in rows]
    )


@router.get(
    "/investigations/{investigation_id}",
    response_model=InvestigationDetail,
    summary="Reopen a past AI investigation (full evidence + trace)",
)
async def get_investigation(
    investigation_id: uuid.UUID, service: InvestigationServiceDep
) -> InvestigationDetail:
    return InvestigationDetail.model_validate(
        await service.get_investigation(investigation_id)
    )


@router.post(
    "/scans/{scan_id}/investigate",
    response_model=InvestigationResponse,
    summary="Investigate a scan with the AI agent (evidence-grounded)",
)
async def investigate_scan(
    scan_id: uuid.UUID, body: InvestigationRequest, service: InvestigationServiceDep
) -> InvestigationResponse:
    result = await service.investigate_scan(scan_id, body.question)
    return InvestigationResponse.model_validate(result.to_dict())


@router.post(
    "/scans/{scan_id}/findings/{finding_id}/investigate",
    response_model=InvestigationResponse,
    summary="Investigate a specific finding with the AI agent",
)
async def investigate_finding(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    body: InvestigationRequest,
    service: InvestigationServiceDep,
) -> InvestigationResponse:
    result = await service.investigate_finding(scan_id, finding_id, body.question)
    return InvestigationResponse.model_validate(result.to_dict())


@router.post(
    "/repository/investigate",
    response_model=InvestigationResponse,
    summary="Investigate across all scans of a repository",
)
async def investigate_repository(
    body: RepositoryInvestigationRequest, service: InvestigationServiceDep
) -> InvestigationResponse:
    result = await service.investigate_repository(body.repository, body.question)
    return InvestigationResponse.model_validate(result.to_dict())


@router.post(
    "/scans/{scan_id}/remediation-plan",
    response_model=RemediationPlanResponse,
    summary="Propose an AI remediation plan (estimate-labeled; requires approval)",
)
async def remediation_plan(
    scan_id: uuid.UUID,
    body: RemediationPlanRequest,
    service: RemediationPlanServiceDep,
) -> RemediationPlanResponse:
    plan = await service.plan(
        scan_id, finding_ids=body.finding_ids, max_targets=body.max_targets
    )
    return RemediationPlanResponse.model_validate(plan.to_dict())


@router.post(
    "/pull-requests/{pr_id}/review",
    response_model=AIReviewResponse,
    summary="AI review of a pull request (advisory, non-authoritative)",
)
async def review_pull_request(
    pr_id: uuid.UUID, service: AiPrReviewServiceDep
) -> AIReviewResponse:
    return AIReviewResponse.model_validate(await service.review_pull_request(pr_id))


@router.post(
    "/scans/{scan_id}/security-review",
    response_model=AIReviewResponse,
    summary="AI security review of a scan (advisory, non-authoritative)",
)
async def security_review(
    scan_id: uuid.UUID, service: AiSecurityReviewServiceDep
) -> AIReviewResponse:
    return AIReviewResponse.model_validate(await service.review_scan(scan_id))
