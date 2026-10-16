"""Containment / remediation planning + approval workflow (Phase 5).

Containment is PLAN-first and approval-gated. Plans are generated from
deterministic, NON-destructive recommendations keyed on the incident's event
categories. A plan is a proposal; it is only acted on after an authorized
approval, and WRITE-class actions are additionally gated behind
``cloud_write_enabled``. Because this build connects to AWS strictly read-only,
no plan execution ever mutates infrastructure - execution records the intended
action, re-reads current state for the audit trail, and reports honestly
(``not_enabled`` for gated writes, ``skipped`` for advisory steps). A successful
record NEVER by itself marks an incident resolved (see verification, M9).

Duplicate execution is prevented by a UNIQUE idempotency key per plan.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from agents.reasoning.sanitize import neutralize
from core.config import Settings
from core.exceptions import ConflictError, NotFoundError, ValidationError
from core.logging import get_logger
from models.cloud import CloudAsset
from models.enums import ContainmentCapability, SecurityEventCategory
from models.incident import (
    ContainmentApproval,
    ContainmentExecution,
    ContainmentPlan,
    Incident,
    IncidentResource,
    IncidentTimelineEntry,
)
from models.security import SecurityEvent

logger = get_logger(__name__)


def _now():  # type: ignore[no-untyped-def]
    from datetime import UTC, datetime

    return datetime.now(UTC)


@dataclass(slots=True)
class _Template:
    title: str
    capability: ContainmentCapability
    proposed_action: str
    expected_benefit: str
    potential_impact: str
    rollback_plan: str
    prerequisites: list[str]
    verification_steps: list[str]
    required_permissions: list[str]


# Deterministic, non-destructive-first containment templates per event category.
_TEMPLATES: dict[str, _Template] = {
    SecurityEventCategory.EXPOSURE.value: _Template(
        title="Restrict public exposure of the affected resource",
        capability=ContainmentCapability.WRITE,
        proposed_action=(
            "Tighten the security group / resource policy so the resource is no "
            "longer reachable from 0.0.0.0/0; restrict to known CIDRs or move private."
        ),
        expected_benefit="Removes direct internet reachability of the exposed resource.",
        potential_impact="Legitimate external clients using the open path may lose access.",
        rollback_plan="Re-add the previous ingress rule / policy from the recorded state.",
        prerequisites=["Confirm no production dependency relies on the public path."],
        verification_steps=["Re-run the exposure rules; confirm exposure is no longer public."],
        required_permissions=[
            "ec2:RevokeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupIngress",
        ],
    ),
    SecurityEventCategory.IDENTITY.value: _Template(
        title="Review and scope down the involved IAM principal",
        capability=ContainmentCapability.PLAN,
        proposed_action=(
            "Review the IAM principal's policies and trust; remove wildcard trust / "
            "excess permissions. Rotate credentials only if compromise is confirmed."
        ),
        expected_benefit="Reduces privilege and blast radius of the identity.",
        potential_impact="Automation using the principal may break if scoped too tightly.",
        rollback_plan="Reattach the previous policy version if access is impacted.",
        prerequisites=["Confirm the principal's legitimate required permissions."],
        verification_steps=["Re-run IAM rules; confirm no wildcard trust / MFA gaps."],
        required_permissions=["iam:GetPolicy", "iam:ListAttachedRolePolicies"],
    ),
    SecurityEventCategory.VULNERABILITY.value: _Template(
        title="Update the vulnerable artifact to a patched version",
        capability=ContainmentCapability.PLAN,
        proposed_action="Update the affected image/dependency to a patched version and redeploy.",
        expected_benefit="Eliminates the known CVE from the running artifact.",
        potential_impact="A new version may introduce behavioural changes; test first.",
        rollback_plan="Redeploy the previous image tag if the update regresses.",
        prerequisites=["A patched version exists and passes CI."],
        verification_steps=["Re-scan the artifact; confirm the CVE is no longer reported."],
        required_permissions=[],
    ),
    SecurityEventCategory.DRIFT.value: _Template(
        title="Reconcile infrastructure drift via Terraform",
        capability=ContainmentCapability.PLAN,
        proposed_action="Review the drift, update Terraform to the intended state, and re-apply.",
        expected_benefit="Restores the resource to its reviewed, version-controlled state.",
        potential_impact="Re-applying may revert out-of-band changes some teams rely on.",
        rollback_plan="Restore the prior Terraform state from version control.",
        prerequisites=["Confirm the Terraform state reflects the intended configuration."],
        verification_steps=["Re-run drift correlation; confirm status IN_SYNC."],
        required_permissions=[],
    ),
    SecurityEventCategory.RUNTIME.value: _Template(
        title="Inspect and contain the affected workload",
        capability=ContainmentCapability.PLAN,
        proposed_action=(
            "Inspect the flagged workload; if malicious, cordon/scale down and collect "
            "forensics. Do NOT auto-isolate production without approval."
        ),
        expected_benefit="Limits a potentially active runtime threat.",
        potential_impact="Cordoning a workload reduces capacity/availability.",
        rollback_plan="Uncordon / scale the workload back up once cleared.",
        prerequisites=["Confirm the alert is a true positive before any disruptive action."],
        verification_steps=["Confirm no further runtime alerts for the workload."],
        required_permissions=[],
    ),
    SecurityEventCategory.THREAT.value: _Template(
        title="Investigate suspected threat and rotate credentials if confirmed",
        capability=ContainmentCapability.PLAN,
        proposed_action=(
            "Investigate the threat finding; if credential compromise is confirmed, "
            "rotate the affected credentials and review recent activity."
        ),
        expected_benefit="Cuts off a confirmed attacker's access path.",
        potential_impact="Rotating credentials disrupts anything still using them.",
        rollback_plan="Not applicable (credential rotation is forward-only).",
        prerequisites=["Confirm compromise via CloudTrail / activity review."],
        verification_steps=["Confirm no further threat findings for the resource/principal."],
        required_permissions=[],
    ),
    SecurityEventCategory.PIPELINE.value: _Template(
        title="Fix the CI/CD security failure and re-run the pipeline",
        capability=ContainmentCapability.PLAN,
        proposed_action=(
            "Address the failing pipeline security gate (update the vulnerable "
            "dependency/image or correct the flagged configuration), then re-run."
        ),
        expected_benefit="Restores a passing security gate and removes the flagged risk.",
        potential_impact="A dependency/image bump may change behaviour; test first.",
        rollback_plan="Revert the pipeline change if it regresses the build.",
        prerequisites=["Review the pipeline failure details."],
        verification_steps=["Re-run the pipeline; confirm the security gate passes."],
        required_permissions=[],
    ),
    SecurityEventCategory.MISCONFIGURATION.value: _Template(
        title="Apply the deterministic finding's recommended fix",
        capability=ContainmentCapability.PLAN,
        proposed_action="Apply the fix from the related deterministic finding(s) and re-scan.",
        expected_benefit="Resolves the underlying misconfiguration.",
        potential_impact="Depends on the specific change; review before applying.",
        rollback_plan="Revert the configuration change if it causes issues.",
        prerequisites=["Review the finding's recommendation."],
        verification_steps=["Re-run the relevant deterministic rules; confirm the finding clears."],
        required_permissions=[],
    ),
}


class ContainmentService:
    """Generate, approve/reject and (gated) execute containment plans."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    async def _incident(self, incident_id: uuid.UUID) -> Incident:
        incident = await self._session.get(Incident, incident_id)
        if incident is None:
            raise NotFoundError(f"Incident {incident_id} not found.")
        return incident

    async def generate_plans(
        self, incident_id: uuid.UUID, *, ai_generated: bool = False
    ) -> list[ContainmentPlan]:
        """Create proposed plans for the incident's event categories (idempotent)."""
        await self._incident(incident_id)
        events = (
            await self._session.scalars(
                select(SecurityEvent).where(SecurityEvent.incident_id == incident_id)
            )
        ).all()
        resources = (
            await self._session.scalars(
                select(IncidentResource).where(IncidentResource.incident_id == incident_id)
            )
        ).all()
        resource_payload = [
            {"resource_id": r.resource_id, "service": r.service, "region": r.region}
            for r in resources
        ]

        existing_titles = {
            p.title
            for p in (
                await self._session.scalars(
                    select(ContainmentPlan).where(
                        ContainmentPlan.incident_id == incident_id
                    )
                )
            ).all()
        }

        # Group related finding ids by category.
        by_category: dict[str, list[str]] = {}
        for ev in events:
            by_category.setdefault(ev.category, []).extend(ev.related_finding_ids or [])

        created: list[ContainmentPlan] = []
        for category, finding_ids in by_category.items():
            template = _TEMPLATES.get(category)
            if template is None or template.title in existing_titles:
                continue
            plan = ContainmentPlan(
                id=uuid.uuid4(),
                incident_id=incident_id,
                title=template.title,
                root_cause=neutralize(category, max_length=120),
                proposed_action=template.proposed_action,
                capability=template.capability.value,
                affected_resources=resource_payload,
                expected_benefit=template.expected_benefit,
                potential_impact=template.potential_impact,
                prerequisites=list(template.prerequisites),
                rollback_plan=template.rollback_plan,
                verification_steps=list(template.verification_steps),
                required_permissions=list(template.required_permissions),
                related_finding_ids=list(dict.fromkeys(finding_ids)),
                status="proposed",
                ai_generated=ai_generated,
            )
            self._session.add(plan)
            created.append(plan)
        await self._session.flush()
        if created:
            incident = await self._incident(incident_id)
            await self._notify(incident, "containment_approval_requested")
        return created

    async def list_plans(self, incident_id: uuid.UUID) -> Sequence[ContainmentPlan]:
        return (
            await self._session.scalars(
                select(ContainmentPlan)
                .where(ContainmentPlan.incident_id == incident_id)
                .order_by(ContainmentPlan.created_at.asc())
            )
        ).all()

    async def get_plan(self, plan_id: uuid.UUID) -> ContainmentPlan:
        plan = await self._session.get(ContainmentPlan, plan_id)
        if plan is None:
            raise NotFoundError(f"Containment plan {plan_id} not found.")
        return plan

    async def approvals_for(self, plan_id: uuid.UUID) -> Sequence[ContainmentApproval]:
        return (
            await self._session.scalars(
                select(ContainmentApproval)
                .where(ContainmentApproval.plan_id == plan_id)
                .order_by(ContainmentApproval.created_at.asc())
            )
        ).all()

    async def executions_for(self, plan_id: uuid.UUID) -> Sequence[ContainmentExecution]:
        return (
            await self._session.scalars(
                select(ContainmentExecution).where(ContainmentExecution.plan_id == plan_id)
            )
        ).all()

    async def approve(
        self, plan_id: uuid.UUID, *, approver: str, reason: str = ""
    ) -> ContainmentPlan:
        plan = await self.get_plan(plan_id)
        if plan.status != "proposed":
            raise ConflictError(f"Only a proposed plan can be approved (is '{plan.status}').")
        if not approver.strip():
            raise ValidationError("An approver identity is required.")
        plan.status = "approved"
        self._session.add(
            ContainmentApproval(
                id=uuid.uuid4(), plan_id=plan_id, decision="approved",
                approver=approver[:255], reason=neutralize(reason, max_length=1000),
            )
        )
        await self._timeline(plan, f"Containment plan approved by {approver}", "action")
        await self._session.flush()
        return plan

    async def reject(
        self, plan_id: uuid.UUID, *, approver: str, reason: str = ""
    ) -> ContainmentPlan:
        plan = await self.get_plan(plan_id)
        if plan.status not in {"proposed", "approved"}:
            raise ConflictError(f"Cannot reject a plan in state '{plan.status}'.")
        plan.status = "rejected"
        self._session.add(
            ContainmentApproval(
                id=uuid.uuid4(), plan_id=plan_id, decision="rejected",
                approver=approver[:255], reason=neutralize(reason, max_length=1000),
            )
        )
        await self._timeline(plan, f"Containment plan rejected by {approver}", "action")
        await self._session.flush()
        return plan

    async def execute(self, plan_id: uuid.UUID, *, actor: str = "") -> ContainmentExecution:
        """Execute an APPROVED plan (gated + idempotent). Never mutates in this build.

        - A plan must be approved. Duplicate execution is blocked by a UNIQUE
          idempotency key.
        - WRITE-class actions require ``cloud_write_enabled`` AND are still not
          performed here (read-only connector): recorded as ``not_enabled``.
        - PLAN/READ actions are advisory: recorded as ``skipped`` (do them manually).
        - Current resource state is re-read for the audit trail (stale-plan guard).
        """
        plan = await self.get_plan(plan_id)
        if plan.status not in {"approved", "executed"}:
            raise ConflictError(
                f"Plan must be approved before execution (is '{plan.status}')."
            )
        # Duplicate-execution guard (belt-and-braces around the UNIQUE constraint).
        existing = await self._session.scalar(
            select(ContainmentExecution).where(ContainmentExecution.plan_id == plan_id)
        )
        if existing is not None:
            raise ConflictError("This plan has already been executed.")

        before_state = await self._snapshot_state(plan)

        if plan.capability == ContainmentCapability.WRITE.value:
            if not self._settings.cloud_write_enabled:
                status, output = (
                    "not_enabled",
                    "Write actions are disabled (cloud_write_enabled=false). No change made.",
                )
            else:
                # This connector is read-only: we never perform the AWS mutation.
                status, output = (
                    "not_enabled",
                    "Automated write execution is not supported by this read-only "
                    "connector. Perform the change manually, then verify.",
                )
        else:
            status, output = (
                "skipped",
                "Advisory plan: perform the documented steps manually, then run verification.",
            )

        execution = ContainmentExecution(
            id=uuid.uuid4(),
            plan_id=plan_id,
            status=status,
            executed_by=actor[:255],
            output=output,
            before_state=before_state,
            after_state={},
            verification={},
            idempotency_key=str(plan_id),
        )
        self._session.add(execution)
        try:
            await self._session.flush()
        except IntegrityError as exc:  # unique idempotency key violated
            raise ConflictError("This plan has already been executed.") from exc

        await self._timeline(
            plan, f"Containment execution recorded: {status}", "action"
        )
        logger.info("containment_execution", plan=str(plan_id), status=status)
        return execution

    async def verify(self, plan_id: uuid.UUID) -> ContainmentExecution:
        """Independently verify a plan by re-running deterministic rules.

        Re-reads each affected resource's CURRENT state and re-evaluates the
        deterministic cloud rules. The baseline "offending" rules come from the
        incident's own cloud-scan events (whose event_type is the rule id). The
        verification outcome is recorded on the execution and is the ONLY thing
        that may mark the plan ``verified`` - a successful execute() never does.

        Outcome status:
        - ``fixed``        : every baseline rule now passes (and some existed);
        - ``partial``      : some baseline rules pass, some still fire;
        - ``unresolved``   : the baseline rules all still fire;
        - ``inconclusive`` : nothing deterministically checkable (e.g. a threat/
          identity signal with no cloud rule) - requires human confirmation.
        """
        plan = await self.get_plan(plan_id)
        execution = await self._session.scalar(
            select(ContainmentExecution).where(ContainmentExecution.plan_id == plan_id)
        )
        if execution is None:
            raise ConflictError("Execute the plan before verifying it.")
        incident = await self._incident(plan.incident_id)

        # Baseline offending rule ids per resource, from the incident's cloud events.
        events = (
            await self._session.scalars(
                select(SecurityEvent).where(
                    SecurityEvent.incident_id == plan.incident_id,
                    SecurityEvent.source_type == "cloud_scan",
                )
            )
        ).all()
        baseline: dict[str, set[str]] = {}
        for ev in events:
            if ev.resource_id and ev.event_type:
                baseline.setdefault(ev.resource_id, set()).add(ev.event_type)

        resource_ids = [r.get("resource_id") for r in plan.affected_resources]
        still_failing: dict[str, list[str]] = {}
        after_state: dict[str, Any] = {}
        checked = 0
        baseline_total = 0

        for rid in resource_ids:
            if not rid or rid not in baseline:
                continue
            baseline_total += len(baseline[rid])
            checked += 1
            current_rules = await self._current_rule_ids(incident, rid)
            after_state[rid] = sorted(current_rules)
            remaining = sorted(baseline[rid] & current_rules)
            if remaining:
                still_failing[rid] = remaining

        remaining_total = sum(len(v) for v in still_failing.values())
        if baseline_total == 0:
            status = "inconclusive"
        elif remaining_total == 0:
            status = "fixed"
        elif remaining_total < baseline_total:
            status = "partial"
        else:
            status = "unresolved"

        execution.after_state = after_state
        execution.verification = {
            "status": status,
            "baseline_rules_total": baseline_total,
            "still_failing": still_failing,
            "resources_checked": checked,
            "verified_at": _now().isoformat(),
            "method": "deterministic_rules_rerun",
        }
        if status == "fixed":
            plan.status = "verified"
        await self._timeline(
            plan, f"Containment verification: {status}", "action"
        )
        await self._session.flush()
        if status in {"unresolved", "partial"}:
            await self._notify(incident, "verification_failed", extra=f"Verification: {status}.")
        logger.info("containment_verify", plan=str(plan_id), status=status)
        return execution

    async def _notify(self, incident: Incident, event_type: str, *, extra: str = "") -> None:
        from services.security.notify import notify_incident

        rows = (
            await self._session.scalars(
                select(IncidentResource).where(IncidentResource.incident_id == incident.id)
            )
        ).all()
        resources = [r.resource_id for r in rows]
        await notify_incident(
            self._session, self._settings, incident, event_type,
            resource_ids=resources, extra=extra,
        )

    async def _current_rule_ids(self, incident: Incident, resource_id: str) -> set[str]:
        """Re-evaluate deterministic rules against the resource's CURRENT state."""
        from services.aws.resources import DiscoveredResource
        from services.aws.rules.base import evaluate_asset
        from services.aws.rules.registry import rules_for_service

        if incident.cloud_account_id is None:
            return set()
        asset = await self._session.scalar(
            select(CloudAsset).where(
                CloudAsset.account_id == incident.cloud_account_id,
                CloudAsset.resource_id == resource_id,
            )
        )
        if asset is None:
            # The resource no longer exists -> no rule can fire against it.
            return set()
        resource = DiscoveredResource(
            service=asset.service, resource_type=asset.resource_type,
            resource_id=asset.resource_id, arn=asset.arn, name=asset.name,
            region=asset.region, state=asset.state, exposure=asset.exposure,
            tags=dict(asset.tags or {}), attributes=dict(asset.attributes or {}),
        )
        findings = evaluate_asset(resource, rules_for_service(asset.service))
        return {f.rule_id for f in findings}

    # ---- helpers -----------------------------------------------------------

    async def _snapshot_state(self, plan: ContainmentPlan) -> dict[str, Any]:
        """Re-read current metadata for the plan's resources (audit/stale-plan guard)."""
        incident = await self._session.get(Incident, plan.incident_id)
        if incident is None or incident.cloud_account_id is None:
            return {"note": "No cloud account; state snapshot unavailable."}
        resource_ids = [r.get("resource_id") for r in plan.affected_resources]
        snapshot: dict[str, Any] = {}
        for rid in resource_ids:
            if not rid:
                continue
            asset = await self._session.scalar(
                select(CloudAsset).where(
                    CloudAsset.account_id == incident.cloud_account_id,
                    CloudAsset.resource_id == rid,
                )
            )
            if asset is not None:
                snapshot[rid] = {"exposure": asset.exposure, "state": asset.state}
        return snapshot

    async def _timeline(self, plan: ContainmentPlan, title: str, evidence_class: str) -> None:
        self._session.add(
            IncidentTimelineEntry(
                id=uuid.uuid4(),
                incident_id=plan.incident_id,
                entry_type="containment",
                title=title[:500],
                detail={"plan_id": str(plan.id), "capability": plan.capability},
                evidence_class=evidence_class,
                occurred_at=_now(),
            )
        )
