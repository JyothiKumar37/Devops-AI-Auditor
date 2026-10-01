"""Persistence models for policy-as-code.

A ``Policy`` is a named, versioned YAML document. ``PolicyVersion`` keeps the
history. ``PolicyAssignment`` binds a policy to a scope (a repository or the
whole workspace, optionally per environment). ``PolicyEvaluation`` records each
evaluation result for audit/trends.
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
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from models.base import GUID, Base


def _now() -> datetime:
    return datetime.now(UTC)


class Policy(Base):
    """A named, versioned policy document (latest YAML stored inline)."""

    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    yaml_text: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    __table_args__ = (UniqueConstraint("name", name="uq_policy_name"),)


class PolicyVersion(Base):
    """An immutable historical version of a policy's YAML."""

    __tablename__ = "policy_versions"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    yaml_text: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        Index("ix_policy_versions_policy", "policy_id", "version"),
    )


class PolicyAssignment(Base):
    """Binds a policy to a scope: a repository full_name or the whole workspace."""

    __tablename__ = "policy_assignments"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False
    )
    scope_type: Mapped[str] = mapped_column(String(16), nullable=False)  # repo | global
    scope_value: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        UniqueConstraint("scope_type", "scope_value", name="uq_policy_assignment_scope"),
        Index("ix_policy_assignments_scope", "scope_type", "scope_value"),
    )


class PolicyEvaluation(Base):
    """A stored policy evaluation result (for audit and history)."""

    __tablename__ = "policy_evaluations"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    subject_type: Mapped[str] = mapped_column(String(16), nullable=False)  # scan | pr | adhoc
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        Index("ix_policy_evaluations_policy", "policy_id", "created_at"),
    )
