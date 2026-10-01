"""SCM integration management endpoints.

Connect a GitHub/GitLab integration with an access token (stored encrypted,
never returned), list/import repositories, and disconnect. These routes are
workspace-global and protected by the existing API-key middleware; the inbound
webhook routes (which external providers call) live separately and are signature
-verified instead.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response, status

from api.dependencies import IntegrationServiceDep
from models.schemas import (
    IntegrationConnectRequest,
    IntegrationListResponse,
    IntegrationRead,
    RemoteRepository,
    RemoteRepositoryListResponse,
    RepositoryImportRequest,
    SCMRepositoryListResponse,
    SCMRepositoryRead,
)

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.post(
    "",
    response_model=IntegrationRead,
    status_code=status.HTTP_201_CREATED,
    summary="Connect an SCM provider (GitHub/GitLab) with an access token",
)
async def connect_integration(
    body: IntegrationConnectRequest, service: IntegrationServiceDep
) -> IntegrationRead:
    """Validate the token against the provider and store it encrypted at rest."""
    integration = await service.connect(
        body.provider, body.token, name=body.name
    )
    return IntegrationRead.model_validate(integration)


@router.get("", response_model=IntegrationListResponse, summary="List integrations")
async def list_integrations(service: IntegrationServiceDep) -> IntegrationListResponse:
    items = await service.list_integrations()
    return IntegrationListResponse(
        total=len(items),
        items=[IntegrationRead.model_validate(i) for i in items],
    )


@router.get(
    "/repositories",
    response_model=SCMRepositoryListResponse,
    summary="List imported repositories (tracked for PR scanning)",
)
async def list_imported_repositories(
    service: IntegrationServiceDep,
) -> SCMRepositoryListResponse:
    items = await service.list_imported_repositories()
    return SCMRepositoryListResponse(
        total=len(items),
        items=[SCMRepositoryRead.model_validate(r) for r in items],
    )


@router.get(
    "/{integration_id}",
    response_model=IntegrationRead,
    summary="Get a single integration",
)
async def get_integration(
    integration_id: uuid.UUID, service: IntegrationServiceDep
) -> IntegrationRead:
    integration = await service.get(integration_id)
    return IntegrationRead.model_validate(integration)


@router.delete(
    "/{integration_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Disconnect an integration",
)
async def delete_integration(
    integration_id: uuid.UUID, service: IntegrationServiceDep
) -> Response:
    await service.delete(integration_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{integration_id}/repositories",
    response_model=RemoteRepositoryListResponse,
    summary="List repositories visible to the integration (live)",
)
async def list_remote_repositories(
    integration_id: uuid.UUID, service: IntegrationServiceDep
) -> RemoteRepositoryListResponse:
    repos = await service.list_remote_repositories(integration_id)
    return RemoteRepositoryListResponse(
        total=len(repos),
        items=[
            RemoteRepository(
                external_id=r.external_id,
                owner=r.owner,
                name=r.name,
                full_name=r.full_name,
                default_branch=r.default_branch,
                web_url=r.web_url,
                private=r.private,
            )
            for r in repos
        ],
    )


@router.post(
    "/{integration_id}/repositories/import",
    response_model=SCMRepositoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Import a repository from an integration for PR scanning",
)
async def import_repository(
    integration_id: uuid.UUID,
    body: RepositoryImportRequest,
    service: IntegrationServiceDep,
) -> SCMRepositoryRead:
    repo = await service.import_repository(integration_id, body.owner, body.name)
    return SCMRepositoryRead.model_validate(repo)
