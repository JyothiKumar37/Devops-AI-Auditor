"""Pull/merge-request feedback: summary comment + commit status.

After an incremental scan (``PRScanService``), this service posts a concise,
deterministic security summary back to the PR and sets a commit status. It
reconciles a SINGLE summary comment per PR (update in place, never duplicate)
using the stored comment id, falling back to a hidden marker in the body.

All numbers come from the Phase 1 deterministic engines - no LLM is involved in
the authoritative status. Feedback posting is best-effort: a provider/API error
here never changes the fact that the scan itself completed.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable

from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.crypto import require_cipher
from core.logging import get_logger
from models.integration import SCMIntegration
from models.pullrequest import PullRequest, PullRequestScan
from services.pr_scan_service import PRScanService
from services.scm import SCMProvider, build_provider
from services.scm.base import CommitStatusState, SCMError, SCMRepo

logger = get_logger(__name__)

# Hidden marker so an existing summary comment can be found even without a stored id.
COMMENT_MARKER = "<!-- devops-ai-auditor:pr-summary -->"
STATUS_CONTEXT = "devops-ai-auditor"

provider_factory: Callable[[str, str, Settings], SCMProvider] = build_provider

_GATE_TO_STATE = {
    "pass": CommitStatusState.SUCCESS,
    "warning": CommitStatusState.SUCCESS,  # visible but non-blocking
    "fail": CommitStatusState.FAILURE,
}
_GATE_LABEL = {"pass": "PASSED", "warning": "WARNING", "fail": "FAILED"}


class PRFeedbackService:
    """Runs a PR scan then reports results to the PR (comment + status)."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        *,
        scan_service: PRScanService | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._scan_service = scan_service or PRScanService(session, settings)

    async def scan_and_report(
        self,
        provider_name: str,
        integration_id: uuid.UUID,
        repo_full_name: str,
        pr_number: int,
    ) -> PullRequestScan:
        integration = await self._session.get(SCMIntegration, integration_id)
        if integration is None:
            raise ValueError(f"Integration {integration_id} not found.")
        token = require_cipher(self._settings).decrypt(integration.encrypted_token)
        provider = provider_factory(provider_name, token, self._settings)
        try:
            repo = await self._scan_service._resolve_repo(  # noqa: SLF001 - internal reuse
                provider, provider_name, repo_full_name
            )
            pr_scan = await self._scan_service.scan(provider, repo, pr_number)
            pull_request = await self._session.get(PullRequest, pr_scan.pull_request_id)
            if pull_request is not None:
                await self._report(provider, repo, pull_request, pr_scan)
            return pr_scan
        finally:
            await provider.aclose()

    async def _report(
        self,
        provider: SCMProvider,
        repo: SCMRepo,
        pull_request: PullRequest,
        pr_scan: PullRequestScan,
    ) -> None:
        """Post/refresh the summary comment and set the commit status."""
        body = self._summary_markdown(pull_request, pr_scan)
        try:
            await self._reconcile_comment(provider, repo, pull_request, body)
        except SCMError as exc:  # feedback is best-effort
            logger.warning("pr_comment_failed", repo=repo.full_name, error=exc.message)

        state = _GATE_TO_STATE.get(pr_scan.gate_status, CommitStatusState.SUCCESS)
        description = self._status_description(pr_scan)
        target = self._settings.public_base_url or pull_request.web_url
        try:
            await provider.set_commit_status(
                repo,
                pull_request.head_sha,
                state,
                context=STATUS_CONTEXT,
                description=description,
                target_url=target or None,
            )
        except SCMError as exc:
            logger.warning("pr_status_failed", repo=repo.full_name, error=exc.message)

        await self._notify_if_failed(repo, pull_request, pr_scan)

    async def _notify_if_failed(
        self, repo: SCMRepo, pull_request: PullRequest, pr_scan: PullRequestScan
    ) -> None:
        """Best-effort: notify subscribed channels when the PR gate fails.

        A notification failure must never affect the scan, so everything here is
        wrapped and swallowed.
        """
        if pr_scan.gate_status != "fail":
            return
        try:
            from services.notification_service import NotificationService
            from services.notifications import Notification, NotificationEvent

            sev = pr_scan.severity_delta or {}
            notification = Notification(
                event=NotificationEvent.PR_SCAN_FAILED.value,
                title=f"PR gate failed: {repo.full_name} #{pull_request.number}",
                body=(
                    f"{pr_scan.new_findings} new finding(s); "
                    f"PR risk {pr_scan.pr_risk_score}/100."
                ),
                severity="high",
                link=self._settings.public_base_url or pull_request.web_url or None,
                fields={
                    "Critical": str(sev.get("critical", 0)),
                    "High": str(sev.get("high", 0)),
                    "Repository": repo.full_name,
                },
            )
            service = NotificationService(self._session, self._settings)
            await service.dispatch(NotificationEvent.PR_SCAN_FAILED.value, notification)
        except Exception as exc:  # noqa: BLE001 - notifications must never fail a scan
            logger.warning("pr_notification_failed", repo=repo.full_name, error=str(exc))

    async def _reconcile_comment(
        self,
        provider: SCMProvider,
        repo: SCMRepo,
        pull_request: PullRequest,
        body: str,
    ) -> None:
        """Ensure exactly one summary comment exists, updated in place."""
        comment_id = pull_request.summary_comment_id
        if comment_id is None:
            # Fall back to locating a prior comment by its hidden marker.
            for existing in await provider.list_comments(repo, pull_request.number):
                if COMMENT_MARKER in existing.body:
                    comment_id = self._native_comment_id(provider.name, pull_request, existing.id)
                    break

        if comment_id is not None:
            try:
                await provider.update_comment(repo, comment_id, body)
                pull_request.summary_comment_id = comment_id
                return
            except SCMError:
                comment_id = None  # comment gone; create a fresh one

        created = await provider.create_comment(repo, pull_request.number, body)
        pull_request.summary_comment_id = self._native_comment_id(
            provider.name, pull_request, created
        )

    @staticmethod
    def _native_comment_id(provider: str, pull_request: PullRequest, raw_id: str) -> str:
        # GitLab note updates need the MR iid; store a composite "iid:note".
        if provider == "gitlab" and ":" not in raw_id:
            return f"{pull_request.number}:{raw_id}"
        return raw_id

    def _summary_markdown(self, pr: PullRequest, scan: PullRequestScan) -> str:
        sev = scan.severity_delta or {}
        label = _GATE_LABEL.get(scan.gate_status, scan.gate_status.upper())
        emoji = {"pass": "✅", "warning": "⚠️", "fail": "🔴"}.get(scan.gate_status, "")
        policy = scan.policy_result or {}
        violations = policy.get("violations", []) if isinstance(policy, dict) else []
        lines = [
            COMMENT_MARKER,
            "## DevOps AI Auditor — PR Security Analysis",
            "",
            f"**Status: {emoji} {label}**",
            "",
            "**New findings**",
            f"- 🔴 Critical: {sev.get('critical', 0)}",
            f"- 🟠 High: {sev.get('high', 0)}",
            f"- 🟡 Medium: {sev.get('medium', 0)}",
            f"- ⚪ Low: {sev.get('low', 0)}",
            "",
            f"**PR risk score:** {scan.pr_risk_score}/100",
            f"**Production readiness:** {scan.readiness_before} → {scan.readiness_after}",
            f"**Changed files:** {scan.changed_files}",
            f"**Fixed in this PR:** {scan.fixed_findings}",
        ]
        if violations:
            lines.append(f"**Policy violations:** {len(violations)}")
        detail = scan.findings_detail or []
        if detail:
            lines += ["", "<details><summary>New findings detail</summary>", ""]
            for f in detail[:25]:
                loc = f.get("file") or "?"
                line = f":{f['line']}" if f.get("line") else ""
                lines.append(
                    f"- **{str(f.get('severity', '')).upper()}** `{f.get('rule_id')}` "
                    f"{f.get('title')} — `{loc}{line}`"
                )
            lines += ["", "</details>"]
        lines += ["", "_Deterministic analysis by DevOps AI Auditor._"]
        return "\n".join(lines)

    @staticmethod
    def _status_description(scan: PullRequestScan) -> str:
        sev = scan.severity_delta or {}
        crit = sev.get("critical", 0)
        high = sev.get("high", 0)
        if scan.new_findings == 0:
            return "No new findings"
        return (
            f"{scan.new_findings} new ({crit} critical, {high} high), "
            f"risk {scan.pr_risk_score}/100"
        )
