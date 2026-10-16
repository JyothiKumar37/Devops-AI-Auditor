"""Compliance assessment + exceptions (Phase 4).

Evaluates a cloud account against a framework's controls using the deterministic
cloud findings as evidence. Statuses:

- PASS           - control applicable, assessed, no (non-excepted) findings.
- FAIL           - control applicable, assessed, has findings.
- NOT_APPLICABLE - no assets of the control's services exist.
- NOT_ASSESSED   - the account has never been synchronized (no evidence yet).

Exceptions (with optional expiry) suppress a control or a specific resource's
findings. We never claim compliance from an absence of data, and never present
results as certification.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.exceptions import NotFoundError, ValidationError
from models.cloud import CloudAccount, CloudAsset, CloudFinding, ComplianceException
from services.audit_service import AuditService
from services.compliance.frameworks import (
    FRAMEWORK_LABELS,
    FRAMEWORKS,
    ControlDef,
    get_framework,
)

PASS = "PASS"
FAIL = "FAIL"
NOT_APPLICABLE = "NOT_APPLICABLE"
NOT_ASSESSED = "NOT_ASSESSED"

_EXCEPTION_REASONS = {"accept_risk", "false_positive", "not_applicable", "compensating_control"}


class ComplianceService:
    """Assess compliance and manage exceptions for a cloud account."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings
        self._audit = AuditService(session)

    async def _account(self, account_pk: uuid.UUID) -> CloudAccount:
        account = await self._session.get(CloudAccount, account_pk)
        if account is None:
            raise NotFoundError(f"Cloud account {account_pk} not found.")
        return account

    def frameworks(self) -> list[dict[str, str]]:
        return [
            {"framework": key, "label": FRAMEWORK_LABELS.get(key, key), "controls": str(len(ctrls))}
            for key, ctrls in FRAMEWORKS.items()
        ]

    async def assess(self, account_pk: uuid.UUID, framework: str) -> dict[str, Any]:
        account = await self._account(account_pk)
        controls = get_framework(framework)
        if not controls:
            raise ValidationError(f"Unknown framework '{framework}'.")

        synced = account.last_synced_at is not None
        services_present = {
            s for (s,) in (
                await self._session.execute(
                    select(CloudAsset.service).where(CloudAsset.account_id == account_pk)
                )
            ).all()
        }
        findings = list(
            (
                await self._session.scalars(
                    select(CloudFinding).where(CloudFinding.account_id == account_pk)
                )
            ).all()
        )
        by_rule: dict[str, list[CloudFinding]] = {}
        for f in findings:
            by_rule.setdefault(f.rule_id, []).append(f)

        now = datetime.now(UTC)
        exceptions = [
            e for e in (
                await self._session.scalars(
                    select(ComplianceException).where(
                        ComplianceException.account_id == account_pk,
                        ComplianceException.framework == framework,
                    )
                )
            ).all()
            if e.is_active(now)
        ]

        results = [
            self._assess_control(ctrl, synced, services_present, by_rule, exceptions)
            for ctrl in controls
        ]
        summary = {PASS: 0, FAIL: 0, NOT_APPLICABLE: 0, NOT_ASSESSED: 0}
        for r in results:
            summary[r["status"]] += 1
        assessed = summary[PASS] + summary[FAIL]
        score = round(100 * summary[PASS] / assessed) if assessed else 0

        return {
            "account_id": str(account_pk),
            "framework": framework,
            "label": FRAMEWORK_LABELS.get(framework, framework),
            "generated_at": now.isoformat(),
            "disclaimer": (
                "Assessment based on available configuration evidence. This is not a "
                "certification."
            ),
            "summary": summary,
            "pass_rate": score,
            "controls": results,
        }

    def _assess_control(
        self,
        ctrl: ControlDef,
        synced: bool,
        services_present: set[str],
        by_rule: dict[str, list[CloudFinding]],
        exceptions: list[ComplianceException],
    ) -> dict[str, Any]:
        if not synced:
            status = NOT_ASSESSED
        elif not (set(ctrl.services) & services_present):
            status = NOT_APPLICABLE
        else:
            status = PASS
        affected: list[dict[str, str]] = []
        finding_ids: list[str] = []

        if status == PASS:
            control_excepted = any(
                e.control_id == ctrl.control_id and e.resource_id is None for e in exceptions
            )
            excepted_resources = {
                e.resource_id for e in exceptions
                if e.control_id == ctrl.control_id and e.resource_id
            }
            hits = [f for rid in ctrl.rule_ids for f in by_rule.get(rid, [])]
            active_hits = [
                f for f in hits
                if not control_excepted and f.resource_id not in excepted_resources
            ]
            if active_hits:
                status = FAIL
                for f in active_hits:
                    finding_ids.append(str(f.id))
                    affected.append(
                        {"resource_id": f.resource_id, "severity": f.severity, "service": f.service}
                    )

        return {
            "control_id": ctrl.control_id,
            "title": ctrl.title,
            "description": ctrl.description,
            "status": status,
            "evidence": f"{len(affected)} finding(s)" if affected else "No violating findings.",
            "affected_resources": affected[:50],
            "finding_ids": finding_ids[:50],
            "remediation": ctrl.remediation,
        }

    # ---- exceptions -------------------------------------------------------

    async def create_exception(
        self,
        account_pk: uuid.UUID,
        *,
        framework: str,
        control_id: str,
        reason: str,
        owner: str,
        note: str = "",
        resource_id: str | None = None,
        approved_by: str = "",
        expires_at: datetime | None = None,
    ) -> ComplianceException:
        await self._account(account_pk)
        if reason not in _EXCEPTION_REASONS:
            raise ValidationError(
                f"Invalid reason '{reason}'. Allowed: {sorted(_EXCEPTION_REASONS)}."
            )
        if not get_framework(framework):
            raise ValidationError(f"Unknown framework '{framework}'.")
        exc = ComplianceException(
            id=uuid.uuid4(), account_id=account_pk, framework=framework,
            control_id=control_id, resource_id=resource_id, reason=reason,
            owner=owner, note=note, approved_by=approved_by, expires_at=expires_at,
        )
        self._session.add(exc)
        await self._session.flush()
        await self._audit.record(
            "compliance.exception.created", resource_type="cloud_account",
            resource_id=str(account_pk),
            detail={"framework": framework, "control_id": control_id, "reason": reason},
        )
        return exc

    async def list_exceptions(self, account_pk: uuid.UUID) -> list[ComplianceException]:
        return list(
            (
                await self._session.scalars(
                    select(ComplianceException).where(
                        ComplianceException.account_id == account_pk
                    ).order_by(ComplianceException.created_at.desc())
                )
            ).all()
        )

    async def delete_exception(self, exception_id: uuid.UUID) -> None:
        await self._session.execute(
            delete(ComplianceException).where(ComplianceException.id == exception_id)
        )
