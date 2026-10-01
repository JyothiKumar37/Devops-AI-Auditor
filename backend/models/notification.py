"""Persistence models for notification channels and delivery history.

A ``NotificationChannel`` stores how to reach a destination (Slack/Teams/webhook
URL or email recipients). Because those URLs often embed secret tokens, the
channel config is stored only as Fernet ciphertext (``encrypted_config``) and is
never returned verbatim by the API - it is masked. ``NotificationDelivery``
records each delivery attempt for observability (sent/failed + error).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from models.base import GUID, Base


def _now() -> datetime:
    return datetime.now(UTC)


class NotificationChannel(Base):
    """A configured notification destination (workspace-global, single-tenant)."""

    __tablename__ = "notification_channels"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    type: Mapped[str] = mapped_column(String(16), nullable=False)  # slack|teams|webhook|email
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Fernet ciphertext of the JSON config (URLs/tokens/recipients). Never returned.
    encrypted_config: Mapped[str] = mapped_column(Text, nullable=False)
    # Subscribed event types (list of NotificationEvent values).
    events: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    __table_args__ = (
        Index("ix_notification_channels_type", "type"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<NotificationChannel {self.type} name={self.name} enabled={self.enabled}>"


class NotificationDelivery(Base):
    """A single delivery attempt of a notification to a channel."""

    __tablename__ = "notification_deliveries"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    channel_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("notification_channels.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # sent | failed
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        Index("ix_notification_deliveries_channel", "channel_id"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<NotificationDelivery channel={self.channel_id} status={self.status}>"
