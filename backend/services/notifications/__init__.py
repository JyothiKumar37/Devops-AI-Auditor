"""Notification providers and factory.

``build_notifier`` is a module-level factory so tests can monkeypatch it to
inject a fake provider without touching the network.
"""

from __future__ import annotations

from typing import Any

from core.config import Settings
from services.notifications.base import (
    ALL_EVENTS,
    Notification,
    NotificationError,
    NotificationEvent,
    NotificationProvider,
    ensure_public_url,
)
from services.notifications.providers import (
    EmailProvider,
    SlackProvider,
    TeamsProvider,
    WebhookProvider,
)

CHANNEL_TYPES = ("slack", "teams", "webhook", "email")


def build_notifier(
    channel_type: str, config: dict[str, Any], settings: Settings
) -> NotificationProvider:
    """Construct a provider for a channel type from its decrypted config."""
    allow_private = settings.notifications_allow_private_hosts
    if channel_type == "slack":
        return SlackProvider(
            _require(config, "webhook_url"), allow_private=allow_private
        )
    if channel_type == "teams":
        return TeamsProvider(
            _require(config, "webhook_url"), allow_private=allow_private
        )
    if channel_type == "webhook":
        return WebhookProvider(
            _require(config, "url"), allow_private=allow_private
        )
    if channel_type == "email":
        recipients = config.get("recipients") or config.get("to") or []
        if isinstance(recipients, str):
            recipients = [recipients]
        return EmailProvider(list(recipients), settings)
    raise NotificationError(f"Unknown channel type '{channel_type}'.")


def _require(config: dict[str, Any], key: str) -> str:
    value = config.get(key)
    if not value or not isinstance(value, str):
        raise NotificationError(f"Channel config missing required field '{key}'.")
    return value


__all__ = [
    "ALL_EVENTS",
    "CHANNEL_TYPES",
    "Notification",
    "NotificationError",
    "NotificationEvent",
    "NotificationProvider",
    "build_notifier",
    "ensure_public_url",
]
