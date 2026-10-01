"""Incremental pull/merge-request scanning.

Given a connected provider and a PR number, this service:

1. reads the PR and its changed files,
2. clones the PR head into an isolated workspace,
3. scans ONLY the changed files (incremental) with the shared scan engine,
4. compares the result against the repository's latest completed base scan to
   separate NEW findings from pre-existing ones (honouring baselines/suppressions),
5. computes the deterministic PR risk and readiness delta (Phase 1 engines),
6. persists a ``PullRequestScan``.

PR feedback (comments/status) and policy evaluation are layered on top in later
milestones; everything here is deterministic and never runs an LLM.
"""

from __future__ import annotations

import shutil
import tempfile
import uuid
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.reasoning.readiness import assess
from core.config import Settings
from core.crypto import require_cipher
from core.logging import get_logger
from models.enums import ScanStatus, Severity
from models.finding import Finding
from models.integration import SCMIntegration, SCMRepository
from models.pullrequest import PullRequest, PullRequestScan
from models.scan import RepositoryFile, Scan
from scanners.finding import RuleFinding
from scanners.low_signal import downrank_if_low_signal
from services.fingerprint import finding_fingerprint
from services.ingestion.git import GitRepositoryCloner
from services.policy_service import PolicyService
from services.risk import RiskInput, assess_risk
from services.scan_engine import scan_repository
from services.scm import build_provider
from services.scm.base import ChangeStatus, SCMProvider, SCMRepo
from services.suppression_service import suppressed_fingerprints

logger = get_logger(__name__)

CloneFn = Callable[[str, str | None, Path], None]


def _v(value: object) -> str:
    """Normalise an enum-or-str to its lowercase string value.

    RuleFinding carries real enums (str(Severity.HIGH) == 'Severity.HIGH' on 3.11),
    while DB-loaded rows may already be plain strings; `.value` handles both.
    """
    return value.value if hasattr(value, "value") else str(value)

# Module-level alias so tests can monkeypatch the provider factory.
provider_factory: Callable[[str, str, Settings], SCMProvider] = build_provider


class PRScanService:
    """Runs an incremental, deterministic scan of a pull/merge request."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        *,
        clone_fn: CloneFn | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._clone_fn = clone_fn or self._default_clone

    def _default_clone(self, clone_url: str, ref: str | None, dest: Path) -> None:
        GitRepositoryCloner(self._settings).clone(clone_url, ref, dest)

    async def scan_by_integration(
        self, integration_id: uuid.UUID, repo_full_name: str, pr_number: int
    ) -> PullRequestScan:
        """Resolve the provider from a stored integration and scan the PR.

        Used by the Celery worker after a webhook. Prefers an imported
        repository row (no extra API call); falls back to a live lookup.
        """
        integration = await self._session.get(SCMIntegration, integration_id)
        if integration is None:
            raise ValueError(f"Integration {integration_id} not found.")
        token = require_cipher(self._settings).decrypt(integration.encrypted_token)
        provider = provider_factory(integration.provider, token, self._settings)
        try:
            repo = await self._resolve_repo(provider, integration.provider, repo_full_name)
            return await self.scan(provider, repo, pr_number)
        finally:
            await provider.aclose()

    async def _resolve_repo(
        self, provider: SCMProvider, provider_name: str, repo_full_name: str
    ) -> SCMRepo:
        row = (
            await self._session.scalars(
                select(SCMRepository).where(
                    SCMRepository.provider == provider_name,
                    SCMRepository.full_name == repo_full_name,
                )
            )
        ).first()
        if row is not None:
            return SCMRepo(
                external_id=row.external_id,
                owner=row.owner,
                name=row.name,
                default_branch=row.default_branch,
                clone_url=row.clone_url,
                web_url=row.web_url,
                private=row.private,
            )
        owner, _, name = repo_full_name.rpartition("/")
        return await provider.get_repository(owner, name)

    async def scan(
        self, provider: SCMProvider, repo: SCMRepo, pr_number: int
    ) -> PullRequestScan:
        pr = await provider.get_pull_request(repo, pr_number)
        changed = await provider.get_changed_files(repo, pr_number)
        changed_paths = {
            cf.path for cf in changed if cf.status is not ChangeStatus.REMOVED
        }

        pull_request = await self._upsert_pull_request(provider.name, repo, pr)

        workspace = Path(tempfile.mkdtemp(prefix="pr-scan-"))
        try:
            self._clone_fn(pr.head_clone_url or repo.clone_url, pr.head_ref, workspace)
            head_findings = scan_repository(
                workspace, self._settings, only_paths=changed_paths
            )
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

        result = await self._evaluate(repo.full_name, changed_paths, head_findings)
        return await self._persist(pull_request, pr.head_sha, len(changed_paths), result)

    # -- comparison ----------------------------------------------------------
    async def _evaluate(
        self,
        repo_full_name: str,
        changed_paths: set[str],
        head_findings: list[RuleFinding],
    ) -> dict:
        suppressed = await suppressed_fingerprints(self._session, repo_full_name)
        base = await self._base_scan(repo_full_name)
        base_items = await self._base_findings(base.id) if base else []
        base_fps = {
            finding_fingerprint(f.rule_id, path, f.evidence) for f, path in base_items
        }

        # Normalise head findings (apply the same low-signal downranking the full
        # pipeline uses so test/example paths are treated consistently).
        head_norm = [downrank_if_low_signal(rf) for rf in head_findings]

        new_findings: list[RuleFinding] = []
        for rf in head_norm:
            fp = finding_fingerprint(rf.rule_id, rf.file_path, rf.evidence)
            if fp in suppressed or fp in base_fps:
                continue
            new_findings.append(rf)

        # Fixed = base findings on changed files that no longer appear in head.
        head_fps = {
            finding_fingerprint(rf.rule_id, rf.file_path, rf.evidence) for rf in head_norm
        }
        fixed = [
            (f, path)
            for f, path in base_items
            if path in changed_paths
            and finding_fingerprint(f.rule_id, path, f.evidence) not in head_fps
            and finding_fingerprint(f.rule_id, path, f.evidence) not in suppressed
        ]

        # Readiness before/after (incremental): base set vs base-with-changed-files
        # swapped for the head findings on those paths.
        base_dicts = [self._finding_dict(f, path) for f, path in base_items]
        base_files = await self._base_files(base.id) if base else []
        readiness_before = assess(base_dicts, base_files).score if base else 100
        after_dicts = [
            self._finding_dict(f, path)
            for f, path in base_items
            if path not in changed_paths
        ] + [self._rule_dict(rf) for rf in head_norm]
        changed_types = [{"file_type": _ext_type(p)} for p in changed_paths]
        readiness_after = assess(after_dicts, base_files + changed_types).score

        # PR risk: the headline is the max risk among NEW findings (deterministic).
        recurrence: dict[str, int] = defaultdict(int)
        for rf in new_findings:
            recurrence[rf.rule_id] += 1
        risk_scores = [
            assess_risk(
                RiskInput(
                    rule_id=rf.rule_id,
                    scanner=rf.scanner,
                    category=_v(rf.category),
                    severity=_v(rf.severity),
                    confidence=_v(rf.confidence),
                    title=rf.title,
                    description=rf.description or "",
                    evidence=rf.evidence,
                    file_path=rf.file_path,
                    recurrence=recurrence[rf.rule_id],
                )
            ).score
            for rf in new_findings
        ]
        pr_risk = max(risk_scores) if risk_scores else 0

        severity_delta: dict[str, int] = {s.value: 0 for s in Severity}
        for rf in new_findings:
            severity_delta[_v(rf.severity)] = severity_delta.get(_v(rf.severity), 0) + 1

        # Policy evaluation (Milestone 6): an assigned policy drives the gate.
        # Fall back to the built-in default gate when no policy is assigned.
        gate = self._default_gate(new_findings)
        policy_result: dict | None = None
        eval_findings = [
            {
                "rule_id": rf.rule_id,
                "scanner": rf.scanner,
                "category": _v(rf.category),
                "severity": _v(rf.severity),
                "confidence": _v(rf.confidence),
                "file": rf.file_path,
                "risk_score": score,
                "is_new": True,
            }
            for rf, score in zip(new_findings, risk_scores, strict=False)
        ]
        policy = await PolicyService(self._session).effective_policy(repo_full_name)
        if policy is not None:
            result = await PolicyService(self._session).evaluate_and_store(
                policy, eval_findings, subject_type="pr", subject_id=repo_full_name
            )
            policy_result = {
                "policy": policy.name,
                **result.as_dict(),
            }
            gate = result.status  # pass | warning | fail

        return {
            "new_findings": new_findings,
            "fixed_count": len(fixed),
            "pr_risk": pr_risk,
            "readiness_before": readiness_before,
            "readiness_after": readiness_after,
            "severity_delta": severity_delta,
            "gate": gate,
            "policy_result": policy_result,
        }

    @staticmethod
    def _default_gate(new_findings: list[RuleFinding]) -> str:
        """Baseline gate until a policy (Milestone 6) is assigned.

        Fail on any new critical/high; warn on new medium; otherwise pass.
        """
        sev = {_v(rf.severity) for rf in new_findings}
        if "critical" in sev or "high" in sev:
            return "fail"
        if "medium" in sev:
            return "warning"
        return "pass"

    async def _base_scan(self, repo_full_name: str) -> Scan | None:
        return (
            await self._session.scalars(
                select(Scan)
                .where(
                    Scan.repository_name == repo_full_name,
                    Scan.status == ScanStatus.COMPLETED,
                )
                .order_by(Scan.created_at.desc())
                .limit(1)
            )
        ).first()

    async def _base_findings(self, scan_id: uuid.UUID) -> list[tuple[Finding, str | None]]:
        findings = list(
            (
                await self._session.scalars(
                    select(Finding).where(Finding.scan_id == scan_id)
                )
            ).all()
        )
        path_rows = (
            await self._session.execute(
                select(RepositoryFile.id, RepositoryFile.path).where(
                    RepositoryFile.scan_id == scan_id
                )
            )
        ).all()
        path_by_id = {row[0]: row[1] for row in path_rows}
        return [(f, path_by_id.get(f.file_id)) for f in findings]

    async def _base_files(self, scan_id: uuid.UUID) -> list[dict]:
        rows = (
            await self._session.execute(
                select(RepositoryFile.file_type).where(RepositoryFile.scan_id == scan_id)
            )
        ).all()
        return [{"file_type": ft} for (ft,) in rows]

    @staticmethod
    def _finding_dict(f: Finding, path: str | None) -> dict:
        return {
            "rule_id": f.rule_id,
            "scanner": f.scanner,
            "category": _v(f.category),
            "severity": _v(f.severity),
            "confidence": _v(f.confidence),
            "title": f.title,
            "file": path,
        }

    @staticmethod
    def _rule_dict(rf: RuleFinding) -> dict:
        return {
            "rule_id": rf.rule_id,
            "scanner": rf.scanner,
            "category": _v(rf.category),
            "severity": _v(rf.severity),
            "confidence": _v(rf.confidence),
            "title": rf.title,
            "file": rf.file_path,
        }

    # -- persistence ---------------------------------------------------------
    async def _upsert_pull_request(
        self, provider: str, repo: SCMRepo, pr: object
    ) -> PullRequest:
        existing = (
            await self._session.scalars(
                select(PullRequest).where(
                    PullRequest.provider == provider,
                    PullRequest.repo_full_name == repo.full_name,
                    PullRequest.number == pr.number,  # type: ignore[attr-defined]
                )
            )
        ).first()
        if existing is not None:
            existing.head_sha = pr.head_sha  # type: ignore[attr-defined]
            existing.title = pr.title  # type: ignore[attr-defined]
            existing.state = pr.state  # type: ignore[attr-defined]
            return existing
        row = PullRequest(
            id=uuid.uuid4(),
            provider=provider,
            repo_full_name=repo.full_name,
            number=pr.number,  # type: ignore[attr-defined]
            title=pr.title,  # type: ignore[attr-defined]
            author=pr.author,  # type: ignore[attr-defined]
            base_ref=pr.base_ref,  # type: ignore[attr-defined]
            head_ref=pr.head_ref,  # type: ignore[attr-defined]
            head_sha=pr.head_sha,  # type: ignore[attr-defined]
            web_url=pr.web_url,  # type: ignore[attr-defined]
            state=pr.state,  # type: ignore[attr-defined]
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def _persist(
        self, pull_request: PullRequest, head_sha: str, changed_count: int, result: dict
    ) -> PullRequestScan:
        new_findings: list[RuleFinding] = result["new_findings"]
        detail = [
            {
                "rule_id": rf.rule_id,
                "scanner": rf.scanner,
                "severity": _v(rf.severity),
                "category": _v(rf.category),
                "title": rf.title,
                "file": rf.file_path,
                "line": rf.line_number,
                "recommendation": rf.recommendation,
            }
            for rf in new_findings
        ]
        scan = PullRequestScan(
            id=uuid.uuid4(),
            pull_request_id=pull_request.id,
            head_sha=head_sha,
            status="completed",
            changed_files=changed_count,
            new_findings=len(new_findings),
            fixed_findings=result["fixed_count"],
            pr_risk_score=result["pr_risk"],
            readiness_before=result["readiness_before"],
            readiness_after=result["readiness_after"],
            severity_delta=result["severity_delta"],
            findings_detail=detail,
            policy_result=result.get("policy_result"),
            gate_status=result["gate"],
            summary="",
        )
        self._session.add(scan)
        await self._session.flush()
        logger.info(
            "pr_scan_completed",
            repo=pull_request.repo_full_name,
            pr=pull_request.number,
            new=len(new_findings),
            gate=result["gate"],
        )
        return scan


_EXT_TYPE = {
    ".tf": "terraform", ".yaml": "yaml", ".yml": "yaml", ".json": "json",
    ".sh": "shell", ".toml": "toml",
}


def _ext_type(path: str) -> str:
    for ext, name in _EXT_TYPE.items():
        if path.endswith(ext):
            return name
    if path.lower().endswith("dockerfile") or "/dockerfile" in path.lower():
        return "dockerfile"
    return "other"
