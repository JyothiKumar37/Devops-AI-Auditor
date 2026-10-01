"""Notification channel management endpoints (CRUD, test-send, deliveries).

Channel secrets are stored encrypted and are never returned - the ``config``
field in responses is masked.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response, status

from api.dependencies import DbSessionDep, SettingsDep
from models.notification import NotificationChannel
from models.schemas import (
    NotificationChannelCreateRequest,
    NotificationChannelListResponse,
    NotificationChannelRead,
    NotificationChannelUpdateRequest,
    NotificationDeliveryRead,
)
from services.notification_service import NotificationService

router = APIRouter(prefix="/notifications", tags=["notifications"])


def _to_read(service: NotificationService, channel: NotificationChannel) -> NotificationChannelRead:
    return NotificationChannelRead(
        id=channel.id,
        type=channel.type,
        name=channel.name,
        enabled=channel.enabled,
        events=channel.events or [],
        config=service.masked_config(channel),
        created_at=channel.created_at,
        updated_at=channel.updated_at,
    )


@router.get("", response_model=NotificationChannelListResponse, summary="List channels")
async def list_channels(
    session: DbSessionDep, settings: SettingsDep
) -> NotificationChannelListResponse:
    service = NotificationService(session, settings)
    items = await service.list_channels()
    return NotificationChannelListResponse(
        total=len(items), items=[_to_read(service, c) for c in items]
    )


@router.post(
    "", response_model=NotificationChannelRead, status_code=status.HTTP_201_CREATED,
    summary="Create a notification channel",
)
async def create_channel(
    body: NotificationChannelCreateRequest, session: DbSessionDep, settings: SettingsDep
) -> NotificationChannelRead:
    service = NotificationService(session, settings)
    channel = await service.create(body.type, body.name, body.config, body.events)
    return _to_read(service, channel)


@router.get(
    "/deliveries",
    response_model=list[NotificationDeliveryRead],
    summary="Recent delivery attempts",
)
async def list_deliveries(
    session: DbSessionDep, settings: SettingsDep, limit: int = 100
) -> list[NotificationDeliveryRead]:
    service = NotificationService(session, settings)
    rows = await service.recent_deliveries(limit=limit)
    return [NotificationDeliveryRead.model_validate(r) for r in rows]


@router.get("/{channel_id}", response_model=NotificationChannelRead, summary="Get a channel")
async def get_channel(
    channel_id: uuid.UUID, session: DbSessionDep, settings: SettingsDep
) -> NotificationChannelRead:
    service = NotificationService(session, settings)
    return _to_read(service, await service.get(channel_id))


@router.put("/{channel_id}", response_model=NotificationChannelRead, summary="Update a channel")
async def update_channel(
    channel_id: uuid.UUID,
    body: NotificationChannelUpdateRequest,
    session: DbSessionDep,
    settings: SettingsDep,
) -> NotificationChannelRead:
    service = NotificationService(session, settings)
    channel = await service.update(
        channel_id,
        name=body.name,
        config=body.config,
        events=body.events,
        enabled=body.enabled,
    )
    return _to_read(service, channel)


@router.delete(
    "/{channel_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a channel"
)
async def delete_channel(
    channel_id: uuid.UUID, session: DbSessionDep, settings: SettingsDep
) -> Response:
    await NotificationService(session, settings).delete(channel_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{channel_id}/test",
    response_model=NotificationDeliveryRead,
    summary="Send a test notification to a channel",
)
async def test_channel(
    channel_id: uuid.UUID, session: DbSessionDep, settings: SettingsDep
) -> NotificationDeliveryRead:
    delivery = await NotificationService(session, settings).test(channel_id)
    return NotificationDeliveryRead.model_validate(delivery)
