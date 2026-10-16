"""Phase 5 models: incidents, their composition, investigations and containment.

An :class:`Incident` groups correlated :class:`~models.security.SecurityEvent`
rows that evidence a single security situation. Correlation is deterministic and
every link carries a human-readable rationale (``IncidentEvent.rationale``) so the
grouping is always explainable - we never assert a relationship we cannot justify.

Containment is PLAN-first and approval-gated: a :class:`ContainmentPlan` is a
proposal; a :class:`ContainmentApproval` records an authorized decision; a
:class:`ContainmentExecution` records what actually happened (and its independent
verification). Write execution is additionally gated by ``cloud_write_enabled``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
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


class Incident(Base):
    """A correlated security incident."""

    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # One of enums.Severity (reused). Derived deterministically from member events.
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    # Deterministic risk score (0-100) + explanation (see prioritization service).
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_rationale: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # One of enums.IncidentStatus.
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="new")

    cloud_account_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=True
    )
    account_ref: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    owner: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    root_cause_hypothesis: Mapped[str] = mapped_column(Text, nullable=False, default="")
    resolution_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Stable correlation key: lets repeated events fold into the SAME open
    # incident instead of spawning duplicates (unique while open).
    correlation_key: Mapped[str] = mapped_column(String(128), nullable=False)
    # Deterministic linkage tokens (shared resource/principal/ip/related-resource)
    # that justify folding events together. Used to match new events to this
    # incident; every attachment records which token matched (the rationale).
    linkage_tokens: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    first_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    __table_args__ = (
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_account", "cloud_account_id", "created_at"),
        Index("ix_incidents_correlation", "correlation_key"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Incident {self.id} status={self.status} sev={self.severity}>"


class IncidentEvent(Base):
    """Associates a security event with an incident + the correlation rationale."""

    __tablename__ = "incident_events"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False
    )
    # Why this event belongs to the incident (correlation signal + evidence).
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    correlation_signal: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        UniqueConstraint("incident_id", "event_id", name="uq_incident_event"),
        Index("ix_incident_events_incident", "incident_id"),
    )


class IncidentResource(Base):
    """An asset affected by an incident (deduplicated per incident)."""

    __tablename__ = "incident_resources"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False)
    resource_arn: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    service: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    region: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    exposure: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="affected")

    __table_args__ = (
        UniqueConstraint("incident_id", "resource_id", name="uq_incident_resource"),
        Index("ix_incident_resources_incident", "incident_id"),
    )


class IncidentTimelineEntry(Base):
    """One entry on an incident's attack/response timeline.

    ``evidence_class`` distinguishes confirmed facts (``confirmed``), deterministic
    inferences (``inferred``), AI hypotheses (``hypothesis``) and response actions
    (``action``) so the UI never presents a guess as a fact.
    """

    __tablename__ = "incident_timeline_entries"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    entry_type: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # confirmed | inferred | hypothesis | action
    evidence_class: Mapped[str] = mapped_column(String(16), nullable=False, default="confirmed")
    actor: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        Index("ix_incident_timeline_incident", "incident_id", "occurred_at"),
    )


class IncidentNote(Base):
    """A human note/comment on an incident."""

    __tablename__ = "incident_notes"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    author: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (Index("ix_incident_notes_incident", "incident_id", "created_at"),)


class IncidentInvestigation(Base):
    """A persisted AI investigation run against an incident (read-only, grounded)."""

    __tablename__ = "incident_investigations"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    question: Mapped[str] = mapped_column(Text, nullable=False, default="")
    answer: Mapped[str] = mapped_column(Text, nullable=False, default="")
    root_cause: Mapped[str] = mapped_column(Text, nullable=False, default="")
    impact: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    recommendations: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    citations: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    trace: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    uncertainties: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    ai_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tool_calls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hallucination_guard_triggered: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        Index("ix_incident_investigations_incident", "incident_id", "created_at"),
    )


class ContainmentPlan(Base):
    """A proposed, approval-gated remediation/containment action for an incident."""

    __tablename__ = "containment_plans"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    root_cause: Mapped[str] = mapped_column(Text, nullable=False, default="")
    proposed_action: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # One of enums.ContainmentCapability (read|plan|write).
    capability: Mapped[str] = mapped_column(String(16), nullable=False, default="plan")
    affected_resources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    expected_benefit: Mapped[str] = mapped_column(Text, nullable=False, default="")
    potential_impact: Mapped[str] = mapped_column(Text, nullable=False, default="")
    prerequisites: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    rollback_plan: Mapped[str] = mapped_column(Text, nullable=False, default="")
    verification_steps: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    required_permissions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    related_finding_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # One of enums.ContainmentStatus.
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="proposed")
    ai_generated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    __table_args__ = (Index("ix_containment_plans_incident", "incident_id"),)


class ContainmentApproval(Base):
    """An authorized decision (approve/reject) on a containment plan."""

    __tablename__ = "containment_approvals"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    plan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("containment_plans.id", ondelete="CASCADE"), nullable=False
    )
    decision: Mapped[str] = mapped_column(String(16), nullable=False)  # approved | rejected
    approver: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (Index("ix_containment_approvals_plan", "plan_id"),)


class ContainmentExecution(Base):
    """The outcome of attempting to execute an approved containment plan.

    Records before/after resource state and independent verification. A successful
    command does NOT by itself mark the incident resolved - verification does.
    """

    __tablename__ = "containment_executions"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    plan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("containment_plans.id", ondelete="CASCADE"), nullable=False
    )
    # succeeded | failed | skipped | not_enabled
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    executed_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    output: Mapped[str] = mapped_column(Text, nullable=False, default="")
    before_state: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    after_state: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    verification: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # idempotency guard: a plan may only be executed once successfully.
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_containment_exec_idempotency"),
        Index("ix_containment_exec_plan", "plan_id"),
    )
