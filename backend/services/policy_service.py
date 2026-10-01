"""Policy management: CRUD, versioning, assignment, and evaluation storage."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.exceptions import NotFoundError, ValidationError
from core.logging import get_logger
from models.policy import Policy, PolicyAssignment, PolicyEvaluation, PolicyVersion
from services.audit_service import AuditService
from services.policy_engine import PolicyError, PolicyResult, evaluate, parse_policy

logger = get_logger(__name__)


class PolicyService:
    """Create/update/evaluate policies and resolve the effective policy."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._audit = AuditService(session)

    def _validate(self, yaml_text: str) -> dict[str, Any]:
        try:
            return parse_policy(yaml_text)
        except PolicyError as exc:
            raise ValidationError(str(exc), code="invalid_policy") from exc

    async def create(self, name: str, yaml_text: str, description: str = "") -> Policy:
        spec = self._validate(yaml_text)
        existing = (
            await self._session.scalars(select(Policy).where(Policy.name == name))
        ).first()
        if existing is not None:
            raise ValidationError(f"A policy named '{name}' already exists.")
        policy = Policy(
            id=uuid.uuid4(),
            name=name or spec["name"],
            description=description,
            yaml_text=yaml_text,
            version=1,
            enabled=True,
        )
        self._session.add(policy)
        await self._session.flush()
        self._session.add(
            PolicyVersion(id=uuid.uuid4(), policy_id=policy.id, version=1, yaml_text=yaml_text)
        )
        await self._audit.record(
            "policy.create",
            resource_type="policy",
            resource_id=str(policy.id),
            detail={"name": policy.name},
        )
        logger.info("policy_created", name=policy.name)
        return policy

    async def get(self, policy_id: uuid.UUID) -> Policy:
        policy = await self._session.get(Policy, policy_id)
        if policy is None:
            raise NotFoundError(f"Policy {policy_id} not found.")
        return policy

    async def list_policies(self) -> Sequence[Policy]:
        return (
            await self._session.scalars(select(Policy).order_by(Policy.name))
        ).all()

    async def update(
        self,
        policy_id: uuid.UUID,
        *,
        yaml_text: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
    ) -> Policy:
        policy = await self.get(policy_id)
        if yaml_text is not None and yaml_text != policy.yaml_text:
            self._validate(yaml_text)
            policy.yaml_text = yaml_text
            policy.version += 1
            self._session.add(
                PolicyVersion(
                    id=uuid.uuid4(), policy_id=policy.id,
                    version=policy.version, yaml_text=yaml_text,
                )
            )
        if description is not None:
            policy.description = description
        if enabled is not None:
            policy.enabled = enabled
        await self._session.flush()
        await self._audit.record(
            "policy.update",
            resource_type="policy",
            resource_id=str(policy.id),
            detail={"name": policy.name, "version": policy.version, "enabled": policy.enabled},
        )
        return policy

    async def delete(self, policy_id: uuid.UUID) -> None:
        policy = await self.get(policy_id)
        await self._audit.record(
            "policy.delete",
            resource_type="policy",
            resource_id=str(policy_id),
            detail={"name": policy.name},
        )
        await self._session.delete(policy)

    async def clone(self, policy_id: uuid.UUID, new_name: str) -> Policy:
        policy = await self.get(policy_id)
        return await self.create(new_name, policy.yaml_text, policy.description)

    async def versions(self, policy_id: uuid.UUID) -> Sequence[PolicyVersion]:
        await self.get(policy_id)
        return (
            await self._session.scalars(
                select(PolicyVersion)
                .where(PolicyVersion.policy_id == policy_id)
                .order_by(PolicyVersion.version.desc())
            )
        ).all()

    async def assign(
        self,
        policy_id: uuid.UUID,
        scope_type: str,
        scope_value: str = "",
        environment: str | None = None,
    ) -> PolicyAssignment:
        if scope_type not in ("repo", "global"):
            raise ValidationError("scope_type must be 'repo' or 'global'.")
        await self.get(policy_id)
        existing = (
            await self._session.scalars(
                select(PolicyAssignment).where(
                    PolicyAssignment.scope_type == scope_type,
                    PolicyAssignment.scope_value == scope_value,
                )
            )
        ).first()
        if existing is not None:
            existing.policy_id = policy_id
            existing.environment = environment
            await self._audit.record(
                "policy.assign",
                resource_type="policy",
                resource_id=str(policy_id),
                detail={"scope_type": scope_type, "scope_value": scope_value},
            )
            return existing
        assignment = PolicyAssignment(
            id=uuid.uuid4(),
            policy_id=policy_id,
            scope_type=scope_type,
            scope_value=scope_value,
            environment=environment,
        )
        self._session.add(assignment)
        await self._session.flush()
        await self._audit.record(
            "policy.assign",
            resource_type="policy",
            resource_id=str(policy_id),
            detail={"scope_type": scope_type, "scope_value": scope_value},
        )
        return assignment

    async def effective_policy(self, repo_full_name: str) -> Policy | None:
        """Return the policy to enforce for a repo: repo assignment, else global."""
        repo_assignment = (
            await self._session.scalars(
                select(PolicyAssignment).where(
                    PolicyAssignment.scope_type == "repo",
                    PolicyAssignment.scope_value == repo_full_name,
                )
            )
        ).first()
        global_assignment = None
        if repo_assignment is None:
            global_assignment = (
                await self._session.scalars(
                    select(PolicyAssignment).where(PolicyAssignment.scope_type == "global")
                )
            ).first()
        assignment = repo_assignment or global_assignment
        if assignment is None:
            return None
        policy = await self._session.get(Policy, assignment.policy_id)
        if policy is None or not policy.enabled:
            return None
        return policy

    async def evaluate_and_store(
        self,
        policy: Policy,
        findings: list[dict[str, Any]],
        *,
        subject_type: str,
        subject_id: str,
        environment: str | None = None,
    ) -> PolicyResult:
        spec = parse_policy(policy.yaml_text)
        result = evaluate(spec, findings, environment=environment)
        self._session.add(
            PolicyEvaluation(
                id=uuid.uuid4(),
                policy_id=policy.id,
                subject_type=subject_type,
                subject_id=subject_id,
                status=result.status,
                result=result.as_dict(),
            )
        )
        await self._session.flush()
        return result
