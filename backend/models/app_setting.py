"""Runtime application settings (mutable key/value overrides).

Small key/value store for operator settings that can change at runtime without a
redeploy - notably the active LLM model. An entry here takes precedence over the
corresponding environment default and is shared by every process (API + worker),
so switching a value (e.g. when a model is overloaded) takes effect everywhere.
"""

from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base, TimestampMixin


class AppSetting(Base, TimestampMixin):
    """A single overridable runtime setting."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
