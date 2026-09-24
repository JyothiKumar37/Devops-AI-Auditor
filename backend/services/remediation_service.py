"""Remediation orchestration.

Turns a stored finding into a reviewable, non-destructive fix proposal, and -
only on explicit approval - applies that fix to the *stored* repository copy
(never a user's repository), re-scans the affected file with the finding's own
scanner, and verifies the finding is actually resolved. If it is, the resolved
finding row is removed; if not, the caller is told manual remediation is needed.

No fix is ever invented: proposals come from the deterministic fixer registry in
``services.remediation``. Rules without a safe transform yield "Manual
remediation required."
"""

from __future__ import annotations

import hashlib
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.exceptions import NotFoundError
from core.logging import get_logger
from models.enums import Confidence
from models.finding import Finding
from models.scan import RepositoryFile
from models.schemas import (
    RemediationProposal,
    RemediationResult,
    RemediationStatus,
)
from scanners.ansible import AnsibleScanner
from scanners.cicd import CICDScanner
from scanners.compose import DockerComposeScanner
from scanners.config import ConfigScanner
from scanners.docker import DockerScanner
from scanners.finding import RuleFinding
from scanners.helm import HelmScanner
from scanners.kubernetes import KubernetesScanner
from scanners.secrets import SecretScanner
from scanners.shell import ShellScanner
from scanners.terraform import TerraformScanner
from services.remediation import (
    MANUAL_REQUIRED,
    build_diff,
    changed_lines,
    propose_fix,
)

logger = get_logger(__name__)


class RemediationService:
    """Proposes and (on approval) applies deterministic fixes to stored files."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    # -- public API ----------------------------------------------------------

    async def propose(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID
    ) -> RemediationProposal:
        """Return a fix proposal for a finding without mutating anything."""
        finding, repo_file = await self._load(scan_id, finding_id)
        confidence = Confidence(finding.confidence)

        if repo_file is None or repo_file.content is None:
            return self._manual_proposal(
                finding,
                confidence,
                repo_file.path if repo_file else None,
                "The file content is not stored, so no automatic fix can be generated.",
            )
        content = repo_file.content

        outcome = propose_fix(
            content, finding.rule_id, finding.line_number, finding.evidence
        )
        if outcome is None:
            return self._manual_proposal(finding, confidence, repo_file.path)

        before, after = changed_lines(content, outcome.new_content)
        return RemediationProposal(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            status=RemediationStatus.PROPOSED,
            summary=outcome.summary,
            rationale=outcome.rationale,
            confidence=confidence,
            file_path=repo_file.path,
            before=before,
            after=after,
            diff=build_diff(repo_file.path, content, outcome.new_content),
            message="A safe fix was generated. Review the diff and approve to apply it.",
        )

    async def apply(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID
    ) -> RemediationResult:
        """Apply the fix to the stored copy, re-scan, and verify resolution.

        This is the approval-gated step: the API only calls it after the user
        has explicitly approved the proposed diff.
        """
        finding, repo_file = await self._load(scan_id, finding_id)

        if repo_file is None or repo_file.content is None:
            return self._manual_result(finding, "No stored content to patch.")
        content = repo_file.content

        outcome = propose_fix(
            content, finding.rule_id, finding.line_number, finding.evidence
        )
        if outcome is None:
            return self._manual_result(finding, MANUAL_REQUIRED)

        diff = build_diff(repo_file.path, content, outcome.new_content)

        # Patch ONLY the stored repository copy - never a user repository.
        repo_file.content = outcome.new_content
        encoded = outcome.new_content.encode("utf-8")
        repo_file.size = len(encoded)
        repo_file.checksum = hashlib.sha256(encoded).hexdigest()

        rescanned = self._rescan(finding.scanner, repo_file.path, outcome.new_content)
        if rescanned is None:
            # No re-scanner for this scanner: we cannot verify, so never claim
            # resolution. (Unreachable for the rules that have fixers today.)
            await self._session.commit()
            return RemediationResult(
                finding_id=finding_id,
                rule_id=finding.rule_id,
                applied=True,
                resolved=False,
                remaining_rule_ids=[finding.rule_id],
                diff=diff,
                message="The fix was applied but this finding's scanner cannot be re-run "
                "to verify it. Manual verification required.",
            )
        remaining = sorted({rf.rule_id for rf in rescanned})
        resolved = not self._still_present(finding, rescanned)

        if resolved:
            await self._session.delete(finding)
            message = "Fix applied to the stored copy and verified: the finding is resolved."
        else:
            message = (
                "The fix was applied to the stored copy but the finding still triggers on "
                "re-scan. Manual remediation required."
            )

        await self._session.commit()
        logger.info(
            "remediation_applied",
            scan_id=str(scan_id),
            finding_id=str(finding_id),
            rule_id=finding.rule_id,
            resolved=resolved,
        )
        return RemediationResult(
            finding_id=finding_id,
            rule_id=finding.rule_id,
            applied=True,
            resolved=resolved,
            remaining_rule_ids=remaining,
            diff=diff,
            message=message,
        )

    # -- internals -----------------------------------------------------------

    async def _load(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID
    ) -> tuple[Finding, RepositoryFile | None]:
        finding = await self._session.get(Finding, finding_id)
        if finding is None or finding.scan_id != scan_id:
            raise NotFoundError(f"Finding {finding_id} not found for scan {scan_id}.")
        repo_file: RepositoryFile | None = None
        if finding.file_id is not None:
            repo_file = await self._session.get(RepositoryFile, finding.file_id)
        return finding, repo_file

    @staticmethod
    def _still_present(finding: Finding, rescanned: list[RuleFinding]) -> bool:
        """Whether the same finding still fires after the patch.

        Matches on (rule_id, line). All fixers edit in place except the
        append-USER fixer, which appends at the end of the file, so the line
        numbers of any other findings are preserved and line matching is safe.
        When the finding has no line, fall back to rule_id presence.
        """
        for rf in rescanned:
            if rf.rule_id != finding.rule_id:
                continue
            if finding.line_number is None or rf.line_number == finding.line_number:
                return True
        return False

    def _rescan(
        self, scanner: str, path: str, content: str
    ) -> list[RuleFinding] | None:
        """Re-run the finding's scanner over the patched file text only.

        Returns None when there is no single-file re-scanner for the scanner,
        so the caller never mistakes an empty result for resolution.
        """
        if scanner == "docker-rules":
            return DockerScanner(self._settings).analyze_text(content, path)
        if scanner == "compose-rules":
            return DockerComposeScanner(self._settings).analyze_text(content, path)
        if scanner == "kubernetes-rules":
            return KubernetesScanner(self._settings).analyze_manifests([(path, content)])
        if scanner == "terraform-rules":
            return TerraformScanner(self._settings).analyze_files([(path, content)])
        if scanner == "secret-scanner":
            return SecretScanner(self._settings).scan_text(path, content)
        if scanner == "shell-rules":
            return ShellScanner(self._settings).analyze_text(content, path)
        if scanner == "ansible-rules":
            return AnsibleScanner(self._settings).analyze_text(content, path)
        if scanner == "config-rules":
            return ConfigScanner(self._settings).analyze_text(content, path)
        if scanner == "helm-rules":
            return HelmScanner(self._settings).analyze_text(content, path)
        if scanner in _CICD_TYPE_BY_SCANNER:
            detected = _CICD_TYPE_BY_SCANNER[scanner]
            return CICDScanner(self._settings).analyze_texts([(path, detected, content)])
        return None

    @staticmethod
    def _manual_proposal(
        finding: Finding,
        confidence: Confidence,
        file_path: str | None,
        message: str = MANUAL_REQUIRED,
    ) -> RemediationProposal:
        return RemediationProposal(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            status=RemediationStatus.MANUAL_REQUIRED,
            summary=MANUAL_REQUIRED,
            rationale=finding.recommendation or "",
            confidence=confidence,
            file_path=file_path,
            before=None,
            after=None,
            diff=None,
            message=message,
        )

    @staticmethod
    def _manual_result(finding: Finding, message: str) -> RemediationResult:
        return RemediationResult(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            applied=False,
            resolved=False,
            remaining_rule_ids=[finding.rule_id],
            diff=None,
            message=message,
        )


_CICD_TYPE_BY_SCANNER = {
    "github-actions-rules": "github_actions",
    "gitlab-ci-rules": "gitlab_ci",
    "jenkins-rules": "jenkins",
}
