"""Persistence models for SCM integrations and imported repositories.

An ``SCMIntegration`` holds the encrypted access token for a provider (GitHub or
GitLab). The token is stored only as ``encrypted_token`` (Fernet ciphertext) and
is never serialised back out through the API. ``SCMRepository`` records a
repository the user has imported from an integration; its ``full_name`` doubles
as the Phase 1 ``repository_name`` identity so scans/diffs/baselines line up.
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
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from models.base import GUID, Base


def _now() -> datetime:
    return datetime.now(UTC)


class SCMIntegration(Base):
    """A connected source-control provider (workspace-global, single-tenant)."""

    __tablename__ = "scm_integrations"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)  # github | gitlab
    account: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="connected")
    api_url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    # Fernet ciphertext of the access token. NEVER returned by the API.
    encrypted_token: Mapped[str] = mapped_column(Text, nullable=False)
    # Fernet ciphertext of the per-integration webhook secret (set when a webhook
    # is registered). Used to validate inbound webhook signatures.
    encrypted_webhook_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    meta: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    __table_args__ = (
        Index("ix_scm_integrations_provider", "provider"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<SCMIntegration {self.provider} account={self.account} status={self.status}>"


class SCMRepository(Base):
    """A repository imported from an integration and tracked for PR scanning."""

    __tablename__ = "scm_repositories"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    integration_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scm_integrations.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    external_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    owner: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # "owner/name" - also the Phase 1 repository_name identity for scans/diffs.
    full_name: Mapped[str] = mapped_column(String(512), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(255), nullable=False, default="main")
    clone_url: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    web_url: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    private: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Policy assigned to this repository (Milestone 6); nullable until assigned.
    policy_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        UniqueConstraint("provider", "full_name", name="uq_scm_repo_provider_fullname"),
        Index("ix_scm_repositories_integration", "integration_id"),
        Index("ix_scm_repositories_full_name", "full_name"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<SCMRepository {self.provider}:{self.full_name}>"
