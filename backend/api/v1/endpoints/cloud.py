"""Cloud (AWS) endpoints (Phase 4).

Read-only cloud intelligence: connect AWS accounts via STS AssumeRole, list them,
re-validate, and disconnect. The external id is never returned; the account id is
always the one AWS verified. Later milestones add assets/findings/network/drift/
compliance under this same ``/cloud`` prefix.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response, status

from api.dependencies import (
    CloudAccountServiceDep,
    CloudDiscoveryServiceDep,
    CloudDriftServiceDep,
    CloudGraphServiceDep,
    CloudKubernetesServiceDep,
    CloudPostureServiceDep,
    ComplianceServiceDep,
)
from models.schemas import (
    CloudAccountConnectRequest,
    CloudAccountListResponse,
    CloudAccountRead,
    CloudAssetListResponse,
    CloudAssetRead,
    CloudChangeListResponse,
    CloudChangeRead,
    CloudDriftCorrelateRequest,
    CloudDriftListResponse,
    CloudDriftRead,
    CloudFindingListResponse,
    CloudFindingRead,
    CloudSnapshotRead,
    ComplianceExceptionCreateRequest,
    ComplianceExceptionListResponse,
    ComplianceExceptionRead,
)

router = APIRouter(prefix="/cloud", tags=["cloud"])


@router.post(
    "/accounts",
    response_model=CloudAccountRead,
    status_code=status.HTTP_201_CREATED,
    summary="Connect an AWS account (read-only, STS AssumeRole)",
)
async def connect_account(
    body: CloudAccountConnectRequest, service: CloudAccountServiceDep
) -> CloudAccountRead:
    account = await service.connect(
        name=body.name,
        role_arn=body.role_arn,
        external_id=body.external_id,
        regions=body.regions,
    )
    return CloudAccountRead.model_validate(account)


@router.get(
    "/accounts",
    response_model=CloudAccountListResponse,
    summary="List connected cloud accounts",
)
async def list_accounts(service: CloudAccountServiceDep) -> CloudAccountListResponse:
    items = await service.list_accounts()
    return CloudAccountListResponse(
        total=len(items), items=[CloudAccountRead.model_validate(a) for a in items]
    )


@router.get(
    "/accounts/{account_id}",
    response_model=CloudAccountRead,
    summary="Get a connected cloud account",
)
async def get_account(
    account_id: uuid.UUID, service: CloudAccountServiceDep
) -> CloudAccountRead:
    return CloudAccountRead.model_validate(await service.get(account_id))


@router.post(
    "/accounts/{account_id}/validate",
    response_model=CloudAccountRead,
    summary="Re-validate an account's role access",
)
async def validate_account(
    account_id: uuid.UUID, service: CloudAccountServiceDep
) -> CloudAccountRead:
    return CloudAccountRead.model_validate(await service.validate(account_id))


@router.delete(
    "/accounts/{account_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Disconnect a cloud account",
)
async def delete_account(
    account_id: uuid.UUID, service: CloudAccountServiceDep
) -> Response:
    await service.delete(account_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/accounts/{account_id}/sync",
    response_model=CloudSnapshotRead,
    summary="Synchronize (discover) an account's AWS resources",
)
async def sync_account(
    account_id: uuid.UUID, service: CloudDiscoveryServiceDep
) -> CloudSnapshotRead:
    return CloudSnapshotRead.model_validate(await service.sync(account_id))


@router.get(
    "/accounts/{account_id}/assets",
    response_model=CloudAssetListResponse,
    summary="List discovered assets for an account",
)
async def list_assets(
    account_id: uuid.UUID,
    service: CloudDiscoveryServiceDep,
    svc: str | None = None,
    region: str | None = None,
    exposure: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> CloudAssetListResponse:
    items, total = await service.list_assets(
        account_id, service=svc, region=region, exposure=exposure,
        limit=limit, offset=offset,
    )
    return CloudAssetListResponse(
        total=total, returned=len(items),
        items=[CloudAssetRead.model_validate(a) for a in items],
    )


@router.get(
    "/assets/{asset_id}",
    response_model=CloudAssetRead,
    summary="Get a discovered cloud asset",
)
async def get_asset(
    asset_id: uuid.UUID, service: CloudDiscoveryServiceDep
) -> CloudAssetRead:
    return CloudAssetRead.model_validate(await service.get_asset(asset_id))


@router.get(
    "/accounts/{account_id}/findings",
    response_model=CloudFindingListResponse,
    summary="List cloud security findings for an account",
)
async def list_findings(
    account_id: uuid.UUID,
    service: CloudPostureServiceDep,
    svc: str | None = None,
    severity: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> CloudFindingListResponse:
    items, total = await service.list_findings(
        account_id, service=svc, severity=severity, limit=limit, offset=offset
    )
    return CloudFindingListResponse(
        total=total, returned=len(items),
        items=[CloudFindingRead.model_validate(f) for f in items],
    )


@router.get(
    "/accounts/{account_id}/posture",
    summary="Cloud security posture (cloud/network/iam domains) for an account",
)
async def get_posture(
    account_id: uuid.UUID, service: CloudPostureServiceDep
) -> dict:
    return await service.posture(account_id)


@router.get(
    "/accounts/{account_id}/network",
    summary="Network exposure graph (nodes + evidence-backed edges)",
)
async def get_network(
    account_id: uuid.UUID, service: CloudGraphServiceDep
) -> dict:
    return await service.network_graph(account_id)


@router.get(
    "/accounts/{account_id}/attack-surface",
    summary="Internet-facing attack surface summary",
)
async def get_attack_surface(
    account_id: uuid.UUID, service: CloudGraphServiceDep
) -> dict:
    return await service.attack_surface(account_id)


@router.get(
    "/accounts/{account_id}/assets/{resource_id}/relationships",
    summary="Relationships for a specific resource",
)
async def get_relationships(
    account_id: uuid.UUID, resource_id: str, service: CloudGraphServiceDep
) -> dict:
    return {"relationships": await service.relationships_for(account_id, resource_id)}


@router.post(
    "/accounts/{account_id}/drift",
    response_model=CloudDriftListResponse,
    summary="Correlate a scan's Terraform against the account's live AWS state",
)
async def correlate_drift(
    account_id: uuid.UUID,
    body: CloudDriftCorrelateRequest,
    service: CloudDriftServiceDep,
) -> CloudDriftListResponse:
    rows = await service.correlate(account_id, body.scan_id)
    return _drift_response(rows)


@router.get(
    "/accounts/{account_id}/drift",
    response_model=CloudDriftListResponse,
    summary="List stored drift for an account",
)
async def list_drift(
    account_id: uuid.UUID, service: CloudDriftServiceDep, status_filter: str | None = None
) -> CloudDriftListResponse:
    rows = await service.list_drift(account_id, status=status_filter)
    return _drift_response(list(rows))


@router.get(
    "/accounts/{account_id}/changes",
    response_model=CloudChangeListResponse,
    summary="List detected cloud changes between synchronizations",
)
async def list_changes(
    account_id: uuid.UUID, service: CloudDiscoveryServiceDep, risk_only: bool = False
) -> CloudChangeListResponse:
    rows = await service.list_changes(account_id, risk_only=risk_only)
    return CloudChangeListResponse(
        total=len(rows), items=[CloudChangeRead.model_validate(c) for c in rows]
    )


@router.get("/compliance/frameworks", summary="List supported compliance frameworks")
async def list_frameworks(service: ComplianceServiceDep) -> dict:
    return {"frameworks": service.frameworks()}


@router.get(
    "/accounts/{account_id}/compliance/{framework}",
    summary="Assess a cloud account against a compliance framework",
)
async def assess_compliance(
    account_id: uuid.UUID, framework: str, service: ComplianceServiceDep
) -> dict:
    return await service.assess(account_id, framework)


@router.post(
    "/accounts/{account_id}/compliance/exceptions",
    response_model=ComplianceExceptionRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a compliance exception (optionally time-limited)",
)
async def create_exception(
    account_id: uuid.UUID,
    body: ComplianceExceptionCreateRequest,
    service: ComplianceServiceDep,
) -> ComplianceExceptionRead:
    exc = await service.create_exception(
        account_id, framework=body.framework, control_id=body.control_id,
        reason=body.reason, owner=body.owner, note=body.note,
        resource_id=body.resource_id, approved_by=body.approved_by,
        expires_at=body.expires_at,
    )
    return ComplianceExceptionRead.model_validate(exc)


@router.get(
    "/accounts/{account_id}/compliance/exceptions",
    response_model=ComplianceExceptionListResponse,
    summary="List compliance exceptions for an account",
)
async def list_exceptions(
    account_id: uuid.UUID, service: ComplianceServiceDep
) -> ComplianceExceptionListResponse:
    items = await service.list_exceptions(account_id)
    return ComplianceExceptionListResponse(
        total=len(items),
        items=[ComplianceExceptionRead.model_validate(e) for e in items],
    )


@router.delete(
    "/compliance/exceptions/{exception_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a compliance exception",
)
async def delete_exception(
    exception_id: uuid.UUID, service: ComplianceServiceDep
) -> Response:
    await service.delete_exception(exception_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/accounts/{account_id}/eks-correlation",
    summary="Correlate EKS clusters with Terraform + Kubernetes evidence",
)
async def eks_correlation(
    account_id: uuid.UUID,
    service: CloudKubernetesServiceDep,
    scan_id: uuid.UUID | None = None,
) -> dict:
    return await service.correlate(account_id, scan_id)


def _drift_response(rows: list) -> CloudDriftListResponse:
    summary: dict[str, int] = {}
    for r in rows:
        summary[r.status] = summary.get(r.status, 0) + 1
    return CloudDriftListResponse(
        total=len(rows),
        items=[CloudDriftRead.model_validate(r) for r in rows],
        summary=summary,
    )
