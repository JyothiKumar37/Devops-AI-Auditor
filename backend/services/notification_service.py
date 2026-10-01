"""Notification channel management and event dispatch.

Channels store their config (URLs/tokens/recipients) encrypted at rest. Dispatch
is best-effort: a delivery failure is recorded as a ``NotificationDelivery`` with
status ``failed`` and SWALLOWED - it never propagates to the triggering scan.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.crypto import require_cipher
from core.exceptions import NotFoundError, ValidationError
from core.logging import get_logger
from models.notification import NotificationChannel, NotificationDelivery
from services.audit_service import AuditService
from services.notifications import (
    ALL_EVENTS,
    CHANNEL_TYPES,
    Notification,
    NotificationError,
    NotificationProvider,
    build_notifier,
)

logger = get_logger(__name__)

# Module-level alias so tests can monkeypatch the provider factory.
notifier_factory: Callable[[str, dict[str, Any], Settings], NotificationProvider] = (
    build_notifier
)

# Config keys that must be masked when returned through the API.
_SECRET_KEYS = ("webhook_url", "url", "secret", "token", "password")


class NotificationService:
    """CRUD for channels, a test-send, and best-effort event dispatch."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings
        self._audit = AuditService(session)

    # ---- CRUD -----------------------------------------------------------------

    async def create(
        self, channel_type: str, name: str, config: dict[str, Any], events: list[str]
    ) -> NotificationChannel:
        if channel_type not in CHANNEL_TYPES:
            raise ValidationError(
                f"Unsupported channel type '{channel_type}'. "
                f"Supported: {', '.join(CHANNEL_TYPES)}."
            )
        if not name.strip():
            raise ValidationError("A channel name is required.")
        clean_events = self._validate_events(events)
        # Validate the config can build a provider before persisting.
        try:
            notifier_factory(channel_type, config, self._settings)
        except NotificationError as exc:
            raise ValidationError(str(exc)) from exc

        cipher = require_cipher(self._settings)  # 503 if encryption not configured
        channel = NotificationChannel(
            id=uuid.uuid4(),
            type=channel_type,
            name=name,
            enabled=True,
            encrypted_config=cipher.encrypt(json.dumps(config)),
            events=clean_events,
        )
        self._session.add(channel)
        await self._session.flush()
        await self._audit.record(
            "notification.create",
            resource_type="notification_channel",
            resource_id=str(channel.id),
            detail={"type": channel_type, "name": name, "events": clean_events},
        )
        logger.info("notification_channel_created", type=channel_type, name=name)
        return channel

    async def get(self, channel_id: uuid.UUID) -> NotificationChannel:
        channel = await self._session.get(NotificationChannel, channel_id)
        if channel is None:
            raise NotFoundError(f"Notification channel {channel_id} not found.")
        return channel

    async def list_channels(self) -> Sequence[NotificationChannel]:
        return (
            await self._session.scalars(
                select(NotificationChannel).order_by(NotificationChannel.created_at.desc())
            )
        ).all()

    async def update(
        self,
        channel_id: uuid.UUID,
        *,
        name: str | None = None,
        config: dict[str, Any] | None = None,
        events: list[str] | None = None,
        enabled: bool | None = None,
    ) -> NotificationChannel:
        channel = await self.get(channel_id)
        if name is not None:
            channel.name = name
        if events is not None:
            channel.events = self._validate_events(events)
        if config is not None:
            try:
                notifier_factory(channel.type, config, self._settings)
            except NotificationError as exc:
                raise ValidationError(str(exc)) from exc
            cipher = require_cipher(self._settings)
            channel.encrypted_config = cipher.encrypt(json.dumps(config))
        if enabled is not None:
            channel.enabled = enabled
        await self._session.flush()
        return channel

    async def delete(self, channel_id: uuid.UUID) -> None:
        channel = await self.get(channel_id)
        await self._audit.record(
            "notification.delete",
            resource_type="notification_channel",
            resource_id=str(channel_id),
            detail={"type": channel.type, "name": channel.name},
        )
        await self._session.delete(channel)
        logger.info("notification_channel_deleted", type=channel.type)

    # ---- Send / dispatch ------------------------------------------------------

    async def test(self, channel_id: uuid.UUID) -> NotificationDelivery:
        """Send a sample notification to one channel and record the result."""
        channel = await self.get(channel_id)
        sample = Notification(
            event="test",
            title="DevOps AI Auditor test notification",
            body=f"This confirms the '{channel.name}' channel is configured correctly.",
            severity="info",
        )
        return await self._deliver(channel, "test", sample)

    async def dispatch(
        self, event_type: str, notification: Notification
    ) -> list[NotificationDelivery]:
        """Send to every enabled channel subscribed to ``event_type``.

        Best-effort: individual failures are recorded and swallowed so a
        notification problem can never fail a scan.
        """
        channels = (
            await self._session.scalars(
                select(NotificationChannel).where(NotificationChannel.enabled.is_(True))
            )
        ).all()
        results: list[NotificationDelivery] = []
        for channel in channels:
            if event_type not in (channel.events or []):
                continue
            results.append(await self._deliver(channel, event_type, notification))
        return results

    async def _deliver(
        self, channel: NotificationChannel, event_type: str, notification: Notification
    ) -> NotificationDelivery:
        status = "sent"
        error: str | None = None
        try:
            config = self._decrypt_config(channel)
            provider = notifier_factory(channel.type, config, self._settings)
            await provider.send(notification)
        except Exception as exc:  # noqa: BLE001 - delivery must never raise upward
            status = "failed"
            error = str(exc)
            logger.warning(
                "notification_delivery_failed",
                channel=str(channel.id),
                channel_type=channel.type,
                event_type=event_type,
                error=error,
            )
        delivery = NotificationDelivery(
            id=uuid.uuid4(),
            channel_id=channel.id,
            event_type=event_type,
            status=status,
            error=error,
        )
        self._session.add(delivery)
        await self._session.flush()
        return delivery

    async def recent_deliveries(self, limit: int = 100) -> Sequence[NotificationDelivery]:
        return (
            await self._session.scalars(
                select(NotificationDelivery)
                .order_by(NotificationDelivery.created_at.desc())
                .limit(limit)
            )
        ).all()

    # ---- Helpers --------------------------------------------------------------

    def _decrypt_config(self, channel: NotificationChannel) -> dict[str, Any]:
        cipher = require_cipher(self._settings)
        return json.loads(cipher.decrypt(channel.encrypted_config))

    def masked_config(self, channel: NotificationChannel) -> dict[str, Any]:
        """Return the channel config with secret values masked for API output."""
        try:
            config = self._decrypt_config(channel)
        except Exception:  # noqa: BLE001 - never leak, never crash listing
            return {}
        masked: dict[str, Any] = {}
        for key, value in config.items():
            if key in _SECRET_KEYS and isinstance(value, str):
                masked[key] = _mask(value)
            else:
                masked[key] = value
        return masked

    @staticmethod
    def _validate_events(events: list[str]) -> list[str]:
        clean = [e for e in dict.fromkeys(events) if e in ALL_EVENTS]
        if not clean:
            raise ValidationError(
                "At least one valid event is required. "
                f"Supported: {', '.join(ALL_EVENTS)}."
            )
        return clean


def _mask(value: str) -> str:
    """Mask a secret, revealing only a short suffix for recognisability."""
    if len(value) <= 8:
        return "***"
    return f"***{value[-4:]}"
