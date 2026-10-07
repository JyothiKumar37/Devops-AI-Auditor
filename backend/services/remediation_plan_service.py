"""AI remediation PLANNER (Phase 3).

Produces a proposed, evidence-grounded remediation plan for a scan - it NEVER
mutates anything. The plan:

- targets real findings (selected by deterministic risk, or caller-specified);
- maps each step to the finding's own deterministic recommendation (so the AI
  cannot contradict the rule engine);
- estimates the production-readiness score impact deterministically by re-running
  the readiness engine over the findings minus the targets (clearly labeled an
  ESTIMATE);
- is marked ``requires_approval=True``. Applying a fix stays with the existing
  deterministic remediation flow, which has its own approval + verification.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from agents.investigation.schemas import RemediationPlan, RemediationStep
from agents.reasoning.readiness import assess
from agents.reasoning.sanitize import neutralize
from core.config import Settings
from core.exceptions import NotFoundError, ValidationError
from models.finding import Finding
from models.scan import RepositoryFile, Scan
from services.fingerprint import finding_fingerprint
from services.risk import RiskInput, assess_risk
from services.suppression_service import suppressed_fingerprints

_MAX_TARGETS = 8


def _v(x: Any) -> str:
    return x.value if hasattr(x, "value") else str(x)


class RemediationPlanService:
    """Builds proposed remediation plans (deterministic estimate; no mutation)."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    async def plan(
        self,
        scan_id: uuid.UUID,
        *,
        finding_ids: list[uuid.UUID] | None = None,
        max_targets: int = 5,
    ) -> RemediationPlan:
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")

        active = await self._active_findings(scan_id, scan.repository_name)
        if not active:
            raise ValidationError("This scan has no active findings to remediate.")

        by_id = {str(f.id): (f, path) for f, path in active}
        targets = self._select_targets(active, finding_ids, max_targets)
        if not targets:
            raise ValidationError(
                "None of the requested findings are active in this scan."
            )
        target_ids = {str(f.id) for f, _ in targets}

        # Deterministic score estimate: readiness over all-active minus the targets.
        files = await self._file_types(scan_id)
        all_dicts = [self._finding_dict(f, p) for f, p in active]
        before = assess(all_dicts, files).score
        after = assess([d for d in all_dicts if d["id"] not in target_ids], files).score

        steps = [
            RemediationStep(
                order=i + 1,
                action=neutralize(
                    f.recommendation or f"Resolve {f.title}", max_length=300
                ),
                finding_id=str(f.id),
                rule_id=f.rule_id,
                file=path,
                deterministic_recommendation=neutralize(f.recommendation or "", max_length=300),
            )
            for i, (f, path) in enumerate(targets)
        ]
        affected_files = sorted({p for _, p in targets if p})
        severities = [_v(f.severity) for f, _ in targets]
        risk_level = self._risk_level(len(affected_files), severities)

        # Validation: every step references a real, active finding in this scan.
        for step in steps:
            assert step.finding_id in by_id  # noqa: S101 - internal invariant

        problem = self._problem_statement(targets)
        return RemediationPlan(
            scan_id=str(scan_id),
            problem=problem,
            root_cause="",  # populated by AI narrative in a later milestone
            steps=steps,
            affected_files=affected_files,
            expected_findings_resolved=sorted(target_ids),
            estimated_score_before=before,
            estimated_score_after=after,
            estimated_score_delta=after - before,
            risk_level=risk_level,
            ai_used=False,
            confidence="medium" if len(targets) >= 1 else "low",
        )

    # ---- helpers -----------------------------------------------------------

    async def _active_findings(
        self, scan_id: uuid.UUID, repository_name: str
    ) -> list[tuple[Finding, str | None]]:
        from agents.investigation.tools._common import load_findings_with_paths

        suppressed = await suppressed_fingerprints(self._session, repository_name)
        return [
            (f, path)
            for (f, path) in await load_findings_with_paths(self._session, scan_id)
            if finding_fingerprint(f.rule_id, path, f.evidence) not in suppressed
        ]

    def _select_targets(
        self,
        active: list[tuple[Finding, str | None]],
        finding_ids: list[uuid.UUID] | None,
        max_targets: int,
    ) -> list[tuple[Finding, str | None]]:
        if finding_ids:
            wanted = {str(fid) for fid in finding_ids}
            return [(f, p) for f, p in active if str(f.id) in wanted]
        # Deterministic: rank by risk and take the top-N.
        recurrence: dict[str, int] = {}
        for f, _ in active:
            recurrence[f.rule_id] = recurrence.get(f.rule_id, 0) + 1
        scored = sorted(
            active,
            key=lambda it: -assess_risk(
                RiskInput(
                    rule_id=it[0].rule_id, scanner=it[0].scanner,
                    category=_v(it[0].category), severity=_v(it[0].severity),
                    confidence=_v(it[0].confidence), title=it[0].title,
                    description=it[0].description, evidence=it[0].evidence,
                    file_path=it[1], recurrence=recurrence.get(it[0].rule_id, 1),
                )
            ).score,
        )
        return scored[: min(max_targets, _MAX_TARGETS)]

    def _finding_dict(self, f: Finding, path: str | None) -> dict[str, Any]:
        return {
            "id": str(f.id),
            "scanner": _v(f.scanner),
            "rule_id": str(f.rule_id),
            "category": _v(f.category),
            "severity": _v(f.severity),
            "confidence": _v(f.confidence),
            "title": f.title,
            "recommendation": f.recommendation or "",
            "file": path,
        }

    async def _file_types(self, scan_id: uuid.UUID) -> list[dict[str, Any]]:
        from sqlalchemy import select

        rows = await self._session.execute(
            select(RepositoryFile.file_type).where(RepositoryFile.scan_id == scan_id)
        )
        return [{"file_type": ft} for (ft,) in rows.all()]

    @staticmethod
    def _risk_level(file_count: int, severities: list[str]) -> str:
        if any(s in {"critical"} for s in severities) or file_count > 5:
            return "medium"
        return "low"

    @staticmethod
    def _problem_statement(targets: list[tuple[Finding, str | None]]) -> str:
        top = targets[0][0]
        extra = f" and {len(targets) - 1} related issue(s)" if len(targets) > 1 else ""
        return neutralize(f"{top.title}{extra}", max_length=300)
