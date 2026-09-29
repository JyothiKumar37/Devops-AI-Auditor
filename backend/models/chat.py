"""Persistence model for the per-scan AI chat.

Stores the running "Ask about this scan" conversation so it survives reloads and
gives the model prior turns for context. Each row is one message (user or
assistant) tied to a scan. `created_at` is set from Python with microsecond
precision so a user message and its assistant reply order deterministically even
on SQLite (whose CURRENT_TIMESTAMP is only second-resolution).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from models.base import GUID, Base


class ChatMessage(Base):
    """A single message in a scan's AI conversation."""

    __tablename__ = "chat_messages"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)  # "user" | "assistant"
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    __table_args__ = (Index("ix_chat_messages_scan_created", "scan_id", "created_at"),)
