"""Inbound SCM webhook endpoints (GitHub/GitLab).

These are called by the providers, not by our own frontend, so they are exempt
from the API-key middleware and authenticated by signature verification instead
(``WebhookService``). Handlers return quickly (202) and hand long work to Celery.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, status

from api.dependencies import DbSessionDep, SettingsDep
from services.webhook_service import WebhookService

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _lower_headers(request: Request) -> dict[str, str]:
    return {k.lower(): v for k, v in request.headers.items()}


@router.post(
    "/github",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive a GitHub webhook (signature-verified)",
)
async def github_webhook(
    request: Request, session: DbSessionDep, settings: SettingsDep
) -> dict:
    body = await request.body()
    service = WebhookService(session=session, settings=settings)
    return await service.handle("github", _lower_headers(request), body)


@router.post(
    "/gitlab",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive a GitLab webhook (token-verified)",
)
async def gitlab_webhook(
    request: Request, session: DbSessionDep, settings: SettingsDep
) -> dict:
    body = await request.body()
    service = WebhookService(session=session, settings=settings)
    return await service.handle("gitlab", _lower_headers(request), body)
