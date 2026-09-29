"""Scan orchestration and persistence.

Coordinates the ingestion pipeline for an uploaded repository archive:

    create Scan (pending) -> save upload (size-capped) -> running
    -> safe extract -> index files -> persist -> completed

The isolated workspace is always removed afterwards (success or failure), and
failures are recorded on the scan row so they are visible via the API. No
repository code is ever executed.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.ai_review import AIReviewScanner
from agents.discovery import RepositoryDiscoveryAgent, category_for
from agents.discovery.types import DiscoveredFile, FileCategory
from core.config import Settings
from core.exceptions import AppError, NotFoundError
from core.logging import get_logger
from models.enums import ScanStatus, Severity, SourceType
from models.finding import Finding
from models.scan import RepositoryFile, Scan
from models.suppression import Suppression
from scanners.ansible import AnsibleScanner
from scanners.cicd import CICDScanner
from scanners.compose import DockerComposeScanner
from scanners.config import ConfigScanner
from scanners.correlation import CorrelationExtractor
from scanners.docker import DockerScanner
from scanners.finding import RuleFinding
from scanners.helm import HelmScanner
from scanners.kubernetes import KubernetesScanner
from scanners.low_signal import downrank_if_low_signal
from scanners.secrets import SecretScanner
from scanners.shell import ShellScanner
from scanners.terraform import TerraformScanner
from services.fingerprint import finding_fingerprint
from services.ingestion.archive import ArchiveValidationError, ZipArchiveExtractor
from services.ingestion.git import GitCloneError, GitRepositoryCloner
from services.ingestion.workspace import Workspace, WorkspaceManager
from services.runtime_config import resolve_settings
from services.suppression_service import suppressed_fingerprints

logger = get_logger(__name__)

_UPLOAD_CHUNK = 1024 * 1024
_MAX_CONTENT_BYTES = 256 * 1024


class UnsupportedArchiveError(AppError):
    status_code = 415
    code = "unsupported_media_type"


class PayloadTooLargeError(AppError):
    status_code = 413
    code = "payload_too_large"


class InvalidArchiveError(AppError):
    status_code = 422
    code = "invalid_archive"


class InvalidGitRepoError(AppError):
    status_code = 422
    code = "invalid_repository"


class GitIngestionDisabledError(AppError):
    status_code = 403
    code = "git_ingestion_disabled"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ScanService:
    """Business logic for creating and querying repository scans."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings
        # Settings with runtime overrides (e.g. LLM model) applied; resolved per
        # scan in `_process_repo` and used by the AI review pass.
        self._ai_settings: Settings | None = None
        self._workspaces = WorkspaceManager(settings)
        self._extractor = ZipArchiveExtractor(settings)
        self._cloner = GitRepositoryCloner(settings)
        self._discovery = RepositoryDiscoveryAgent()

    # -- queries -------------------------------------------------------------

    async def list_scans(self, limit: int, offset: int) -> tuple[list[tuple[Scan, int]], int]:
        """Return a page of scans with their file counts, plus the total count."""
        total = await self._session.scalar(select(func.count()).select_from(Scan)) or 0

        file_count = func.count(RepositoryFile.id)
        stmt = (
            select(Scan, file_count)
            .outerjoin(RepositoryFile, RepositoryFile.scan_id == Scan.id)
            .group_by(Scan.id)
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = (await self._session.execute(stmt)).all()
        return [(row[0], row[1]) for row in rows], int(total)

    async def get_scan(self, scan_id: uuid.UUID) -> tuple[Scan, int]:
        """Return a scan and its file count, or raise NotFoundError."""
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")
        count = await self._session.scalar(
            select(func.count(RepositoryFile.id)).where(RepositoryFile.scan_id == scan_id)
        )
        return scan, int(count or 0)

    async def get_files(
        self, scan_id: uuid.UUID, limit: int, offset: int
    ) -> tuple[list[RepositoryFile], int]:
        """Return a page of files for a scan, or raise NotFoundError."""
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")

        total = await self._session.scalar(
            select(func.count(RepositoryFile.id)).where(RepositoryFile.scan_id == scan_id)
        )
        stmt = (
            select(RepositoryFile)
            .where(RepositoryFile.scan_id == scan_id)
            .order_by(RepositoryFile.path)
            .limit(limit)
            .offset(offset)
        )
        files = list((await self._session.scalars(stmt)).all())
        return files, int(total or 0)

    async def get_discovery(
        self, scan_id: uuid.UUID
    ) -> tuple[dict[str, list[RepositoryFile]], int]:
        """Return the scan's files grouped by discovery category.

        Grouping is derived deterministically from the stored file types, so it
        needs no access to the (already cleaned-up) extracted files.
        """
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")

        stmt = (
            select(RepositoryFile)
            .where(RepositoryFile.scan_id == scan_id)
            .order_by(RepositoryFile.path)
        )
        files = list((await self._session.scalars(stmt)).all())

        groups: dict[str, list[RepositoryFile]] = {c.value: [] for c in FileCategory}
        for repo_file in files:
            groups[category_for(repo_file.file_type).value].append(repo_file)
        return groups, len(files)

    async def get_findings(
        self,
        scan_id: uuid.UUID,
        *,
        severity: str | None = None,
        category: str | None = None,
        scanner: str | None = None,
        confidence: str | None = None,
        file_id: uuid.UUID | None = None,
        file_type: str | None = None,
        suppressed: bool | None = None,
    ) -> tuple[list[Finding], dict[str, int], int]:
        """Return a scan's findings (optionally filtered), severity counts and the
        number of suppressed (baselined) findings.

        Each returned finding is annotated with its baseline status
        (`suppressed`, `suppression_reason`, `suppression_note`). The optional
        `suppressed` filter keeps only suppressed or only active findings.
        """
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")

        conditions = [Finding.scan_id == scan_id]
        if severity:
            conditions.append(Finding.severity == severity)
        if category:
            conditions.append(Finding.category == category)
        if scanner:
            conditions.append(Finding.scanner == scanner)
        if confidence:
            conditions.append(Finding.confidence == confidence)
        if file_id:
            conditions.append(Finding.file_id == file_id)
        if file_type:
            subquery = select(RepositoryFile.id).where(
                RepositoryFile.scan_id == scan_id, RepositoryFile.file_type == file_type
            )
            conditions.append(Finding.file_id.in_(subquery))

        stmt = select(Finding).where(*conditions)
        findings = list((await self._session.scalars(stmt)).all())

        # Annotate baseline status from the repository's suppressions.
        await self._annotate_suppression(scan, findings)
        suppressed_count = sum(1 for f in findings if getattr(f, "suppressed", False))
        if suppressed is not None:
            findings = [
                f for f in findings if bool(getattr(f, "suppressed", False)) is suppressed
            ]

        # Deterministic ordering: most severe first, then by file and line.
        findings.sort(
            key=lambda f: (
                -Severity(f.severity).rank,
                f.rule_id,
                f.line_number or 0,
            )
        )

        # Severity counts always cover the (unfiltered) scan for an overview.
        counts = {s.value: 0 for s in Severity}
        count_rows = await self._session.execute(
            select(Finding.severity, func.count())
            .where(Finding.scan_id == scan_id)
            .group_by(Finding.severity)
        )
        for sev, count in count_rows.all():
            counts[str(sev)] = int(count)

        return findings, counts, suppressed_count

    async def _annotate_suppression(
        self, scan: Scan, findings: list[Finding]
    ) -> None:
        """Tag findings with the repository's baseline (suppression) status."""
        suppressions = {
            row.fingerprint: row
            for row in (
                await self._session.scalars(
                    select(Suppression).where(
                        Suppression.repository_name == scan.repository_name
                    )
                )
            ).all()
        }
        path_rows = (
            await self._session.execute(
                select(RepositoryFile.id, RepositoryFile.path).where(
                    RepositoryFile.scan_id == scan.id
                )
            )
        ).all()
        path_by_file: dict[uuid.UUID, str] = {row[0]: row[1] for row in path_rows}
        for finding in findings:
            path = path_by_file.get(finding.file_id, "") if finding.file_id else ""
            match = suppressions.get(
                finding_fingerprint(finding.rule_id, path, finding.evidence)
            )
            finding.suppressed = match is not None  # type: ignore[attr-defined]
            finding.suppression_reason = match.reason if match else None  # type: ignore[attr-defined]
            finding.suppression_note = match.note if match else None  # type: ignore[attr-defined]

    async def get_file(self, scan_id: uuid.UUID, file_id: uuid.UUID) -> RepositoryFile:
        """Return a repository file (including its content), or raise NotFoundError."""
        repo_file = await self._session.get(RepositoryFile, file_id)
        if repo_file is None or repo_file.scan_id != scan_id:
            raise NotFoundError(f"File {file_id} not found for scan {scan_id}.")
        return repo_file

    async def get_stats(self) -> dict[str, Any]:
        """Compute dashboard aggregates across all scans (readiness scored on demand)."""
        from agents.reasoning.readiness import assess

        total_scans = int(await self._session.scalar(select(func.count()).select_from(Scan)) or 0)
        repositories = int(
            await self._session.scalar(
                select(func.count(func.distinct(Scan.repository_name)))
            )
            or 0
        )

        sev_counts: dict[str, int] = {}
        for sev, count in (
            await self._session.execute(
                select(Finding.severity, func.count()).group_by(Finding.severity)
            )
        ).all():
            sev_counts[str(sev)] = int(count)

        # Findings grouped by category (where the risk concentrates).
        category_counts: dict[str, int] = {}
        for cat, count in (
            await self._session.execute(
                select(Finding.category, func.count()).group_by(Finding.category)
            )
        ).all():
            category_counts[str(cat)] = int(count)

        # Most frequently recurring rules across all scans.
        top_rules = [
            {"rule_id": str(rule_id), "count": int(count)}
            for rule_id, count in (
                await self._session.execute(
                    select(Finding.rule_id, func.count())
                    .group_by(Finding.rule_id)
                    .order_by(func.count().desc())
                    .limit(8)
                )
            ).all()
        ]

        # Average readiness across completed scans (deterministic engine, no LLM),
        # plus the per-scan score and how many scans are production-ready.
        completed = (
            await self._session.scalars(
                select(Scan).where(Scan.status == ScanStatus.COMPLETED)
            )
        ).all()
        scores: list[int] = []
        readiness_by_scan: dict[uuid.UUID, int] = {}
        repositories_ready = 0
        suppressed_by_repo: dict[str, set[str]] = {}
        for scan in completed:
            if scan.repository_name not in suppressed_by_repo:
                suppressed_by_repo[scan.repository_name] = await suppressed_fingerprints(
                    self._session, scan.repository_name
                )
            suppressed = suppressed_by_repo[scan.repository_name]
            findings = [
                self._finding_dict(f)
                for (f, path) in await self._findings_with_paths(scan.id)
                if finding_fingerprint(f.rule_id, path, f.evidence) not in suppressed
            ]
            files = [
                {"file_type": ft}
                for (ft,) in (
                    await self._session.execute(
                        select(RepositoryFile.file_type).where(
                            RepositoryFile.scan_id == scan.id
                        )
                    )
                ).all()
            ]
            report = assess(findings, files)
            scores.append(report.score)
            readiness_by_scan[scan.id] = report.score
            if report.ready:
                repositories_ready += 1
        average_readiness = round(sum(scores) / len(scores), 1) if scores else 0.0

        latest_rows, _ = await self.list_scans(limit=8, offset=0)
        return {
            "total_scans": total_scans,
            "repositories_scanned": repositories,
            "repositories_ready": repositories_ready,
            "critical_issues": sev_counts.get("critical", 0),
            "high_issues": sev_counts.get("high", 0),
            "average_readiness": average_readiness,
            "total_findings": sum(sev_counts.values()),
            "severity_counts": sev_counts,
            "category_counts": category_counts,
            "top_rules": top_rules,
            "readiness_by_scan": readiness_by_scan,
            "latest_scans": latest_rows,
        }

    @staticmethod
    def _finding_dict(finding: Finding) -> dict[str, object]:
        return {
            "id": str(finding.id),
            "scanner": str(finding.scanner),
            "rule_id": str(finding.rule_id),
            "category": str(finding.category),
            "severity": str(finding.severity),
            "confidence": str(finding.confidence),
            "file": None,
            "title": finding.title,
            "recommendation": finding.recommendation or "",
        }

    # -- diffing -------------------------------------------------------------

    async def get_diff(
        self, head_id: uuid.UUID, base_id: uuid.UUID | None = None
    ) -> dict[str, Any]:
        """Compare a scan's findings against a previous (or explicit) base scan.

        When `base_id` is omitted the most recent completed scan of the same
        repository (created before `head`) is used. Findings are matched by a
        line-independent fingerprint and partitioned into new / fixed / unchanged,
        and the deterministic readiness score is reported for both sides.
        """
        head = await self._session.get(Scan, head_id)
        if head is None:
            raise NotFoundError(f"Scan {head_id} not found.")

        if base_id is not None:
            base = await self._session.get(Scan, base_id)
            if base is None:
                raise NotFoundError(f"Base scan {base_id} not found.")
        else:
            base = await self._find_previous_scan(head)

        head_items = await self._findings_with_paths(head_id)
        base_items = await self._findings_with_paths(base.id) if base else []

        head_groups = self._group_by_fingerprint(head_items)
        base_groups = self._group_by_fingerprint(base_items)

        new_items: list[tuple[Finding, str | None]] = []
        fixed_items: list[tuple[Finding, str | None]] = []
        unchanged_items: list[tuple[Finding, str | None]] = []
        for fingerprint in set(base_groups) | set(head_groups):
            base_group = base_groups.get(fingerprint, [])
            head_group = head_groups.get(fingerprint, [])
            common = min(len(base_group), len(head_group))
            unchanged_items.extend(head_group[:common])
            if len(head_group) > len(base_group):
                new_items.extend(head_group[common:])
            elif len(base_group) > len(head_group):
                fixed_items.extend(base_group[common:])

        new_items = self._sort_diff(new_items)
        fixed_items = self._sort_diff(fixed_items)
        unchanged_items = self._sort_diff(unchanged_items)

        head_readiness = await self._readiness_score(head_id)
        base_readiness = await self._readiness_score(base.id) if base else None
        readiness_delta = (
            head_readiness - base_readiness if base_readiness is not None else None
        )

        return {
            "base_scan_id": base.id if base else None,
            "head_scan_id": head.id,
            "repository_name": head.repository_name,
            "base_created_at": base.created_at if base else None,
            "head_created_at": head.created_at,
            "base_readiness": base_readiness,
            "head_readiness": head_readiness,
            "readiness_delta": readiness_delta,
            "summary": {
                "new": len(new_items),
                "fixed": len(fixed_items),
                "unchanged": len(unchanged_items),
                "base_total": len(base_items),
                "head_total": len(head_items),
            },
            "new_severity_counts": self._severity_counts(new_items),
            "fixed_severity_counts": self._severity_counts(fixed_items),
            "new_findings": [self._diff_finding(item) for item in new_items],
            "fixed_findings": [self._diff_finding(item) for item in fixed_items],
            "unchanged_findings": [self._diff_finding(item) for item in unchanged_items],
        }

    async def _find_previous_scan(self, head: Scan) -> Scan | None:
        """The most recent completed scan of the same repo before `head`."""
        stmt = (
            select(Scan)
            .where(
                Scan.repository_name == head.repository_name,
                Scan.id != head.id,
                Scan.status == ScanStatus.COMPLETED,
                Scan.created_at < head.created_at,
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        return await self._session.scalar(stmt)

    async def _findings_with_paths(
        self, scan_id: uuid.UUID
    ) -> list[tuple[Finding, str | None]]:
        """Load a scan's findings paired with their (resolved) repository path."""
        stmt = (
            select(Finding, RepositoryFile.path)
            .outerjoin(RepositoryFile, Finding.file_id == RepositoryFile.id)
            .where(Finding.scan_id == scan_id)
        )
        rows = (await self._session.execute(stmt)).all()
        return [(row[0], row[1]) for row in rows]

    async def _readiness_score(self, scan_id: uuid.UUID) -> int:
        """Deterministic readiness score (0-100) for a scan, excluding suppressed
        (baselined) findings so accepted risks do not count against it."""
        from agents.reasoning.readiness import assess

        scan = await self._session.get(Scan, scan_id)
        suppressed = (
            await suppressed_fingerprints(self._session, scan.repository_name)
            if scan
            else set()
        )
        findings = [
            self._finding_dict(f)
            for (f, path) in await self._findings_with_paths(scan_id)
            if finding_fingerprint(f.rule_id, path, f.evidence) not in suppressed
        ]
        files = [
            {"file_type": ft}
            for (ft,) in (
                await self._session.execute(
                    select(RepositoryFile.file_type).where(
                        RepositoryFile.scan_id == scan_id
                    )
                )
            ).all()
        ]
        return assess(findings, files).score

    @staticmethod
    def _fingerprint(item: tuple[Finding, str | None]) -> tuple[str, str, str]:
        """Line-independent identity for matching a finding across scans."""
        finding, path = item
        return (finding.rule_id, path or "", (finding.evidence or "").strip())

    def _group_by_fingerprint(
        self, items: list[tuple[Finding, str | None]]
    ) -> dict[tuple[str, str, str], list[tuple[Finding, str | None]]]:
        groups: dict[tuple[str, str, str], list[tuple[Finding, str | None]]] = defaultdict(
            list
        )
        for item in items:
            groups[self._fingerprint(item)].append(item)
        return groups

    @staticmethod
    def _sort_diff(
        items: list[tuple[Finding, str | None]],
    ) -> list[tuple[Finding, str | None]]:
        return sorted(
            items,
            key=lambda it: (
                -Severity(it[0].severity).rank,
                it[0].rule_id,
                it[1] or "",
                it[0].line_number or 0,
            ),
        )

    @staticmethod
    def _severity_counts(items: list[tuple[Finding, str | None]]) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding, _ in items:
            counts[str(finding.severity)] = counts.get(str(finding.severity), 0) + 1
        return counts

    @staticmethod
    def _diff_finding(item: tuple[Finding, str | None]) -> dict[str, Any]:
        finding, path = item
        return {
            "rule_id": finding.rule_id,
            "scanner": finding.scanner,
            "category": str(finding.category),
            "severity": str(finding.severity),
            "confidence": str(finding.confidence),
            "title": finding.title,
            "file": path,
            "line": finding.line_number,
            "recommendation": finding.recommendation or "",
        }

    # -- scanning ------------------------------------------------------------

    def _run_scanners(
        self,
        repo_root: Path,
        discovered_files: list[DiscoveredFile],
        scan_id: uuid.UUID,
        file_id_by_path: dict[str, uuid.UUID],
    ) -> list[Finding]:
        """Run available scanners over the discovered files and build Finding rows."""
        findings: list[Finding] = []

        docker_files = [f for f in discovered_files if f.category == FileCategory.DOCKER]
        if docker_files:
            docker_scanner = DockerScanner(self._settings)
            for discovered in docker_files:
                file_id = file_id_by_path.get(discovered.path)
                for rule_finding in docker_scanner.analyze_file(repo_root, discovered.path):
                    findings.append(self._to_finding(scan_id, file_id, rule_finding))

        compose_files = [f for f in discovered_files if f.category == FileCategory.COMPOSE]
        if compose_files:
            compose_scanner = DockerComposeScanner(self._settings)
            for discovered in compose_files:
                file_id = file_id_by_path.get(discovered.path)
                for rule_finding in compose_scanner.analyze_file(repo_root, discovered.path):
                    findings.append(self._to_finding(scan_id, file_id, rule_finding))

        # Kubernetes manifests are analysed together (whole-repo) so cross-file
        # relationships can be checked.
        k8s_files = [f for f in discovered_files if f.category == FileCategory.KUBERNETES]
        if k8s_files:
            k8s_scanner = KubernetesScanner(self._settings)
            paths = [f.path for f in k8s_files]
            for rule_finding in k8s_scanner.analyze_repo(repo_root, paths):
                file_id = file_id_by_path.get(rule_finding.file_path)
                findings.append(self._to_finding(scan_id, file_id, rule_finding))

        # Terraform files are grouped by module directory and analysed together.
        tf_files = [f for f in discovered_files if f.category == FileCategory.TERRAFORM]
        if tf_files:
            tf_scanner = TerraformScanner(self._settings)
            paths = [f.path for f in tf_files]
            for rule_finding in tf_scanner.analyze_repo(repo_root, paths):
                file_id = file_id_by_path.get(rule_finding.file_path)
                findings.append(self._to_finding(scan_id, file_id, rule_finding))

        # Helm chart files (Chart.yaml / values.yaml / templates) analysed individually.
        helm_files = [f for f in discovered_files if f.category == FileCategory.HELM]
        if helm_files:
            helm_scanner = HelmScanner(self._settings)
            for discovered in helm_files:
                file_id = file_id_by_path.get(discovered.path)
                for rule_finding in helm_scanner.analyze_file(repo_root, discovered.path):
                    findings.append(self._to_finding(scan_id, file_id, rule_finding))

        # Ansible playbooks/roles/vars are analysed individually.
        ansible_files = [f for f in discovered_files if f.category == FileCategory.ANSIBLE]
        if ansible_files:
            ansible_scanner = AnsibleScanner(self._settings)
            for discovered in ansible_files:
                file_id = file_id_by_path.get(discovered.path)
                for rule_finding in ansible_scanner.analyze_file(repo_root, discovered.path):
                    findings.append(self._to_finding(scan_id, file_id, rule_finding))

        # Shell scripts are analysed individually (line/regex based rules).
        shell_files = [f for f in discovered_files if f.category == FileCategory.SHELL]
        if shell_files:
            shell_scanner = ShellScanner(self._settings)
            for discovered in shell_files:
                file_id = file_id_by_path.get(discovered.path)
                for rule_finding in shell_scanner.analyze_file(repo_root, discovered.path):
                    findings.append(self._to_finding(scan_id, file_id, rule_finding))

        # CI/CD files dispatched by platform (GitHub Actions / GitLab CI / Jenkins).
        cicd_files = [f for f in discovered_files if f.category == FileCategory.CICD]
        if cicd_files:
            cicd_scanner = CICDScanner(self._settings)
            entries = [(f.path, f.detected_type) for f in cicd_files]
            for rule_finding in cicd_scanner.analyze_repo(repo_root, entries):
                file_id = file_id_by_path.get(rule_finding.file_path)
                findings.append(self._to_finding(scan_id, file_id, rule_finding))

        # Generic configuration files (YAML/JSON/TOML/ini/env) analysed individually.
        config_files = [
            f for f in discovered_files if f.category == FileCategory.CONFIGURATION
        ]
        if config_files:
            config_scanner = ConfigScanner(self._settings)
            for discovered in config_files:
                file_id = file_id_by_path.get(discovered.path)
                for rule_finding in config_scanner.analyze_file(repo_root, discovered.path):
                    findings.append(self._to_finding(scan_id, file_id, rule_finding))

        # Secret scanning runs over every file (secrets can appear anywhere).
        secret_scanner = SecretScanner(self._settings)
        all_paths = [f.path for f in discovered_files]
        for rule_finding in secret_scanner.analyze_repo(repo_root, all_paths):
            file_id = file_id_by_path.get(rule_finding.file_path)
            findings.append(self._to_finding(scan_id, file_id, rule_finding))

        # Optional complementary AI review (gated on a configured LLM provider).
        # Its findings augment - never replace - the deterministic ones above.
        self._run_ai_review(repo_root, discovered_files, scan_id, file_id_by_path, findings)

        return findings

    def _run_ai_review(
        self,
        repo_root: Path,
        discovered_files: list[DiscoveredFile],
        scan_id: uuid.UUID,
        file_id_by_path: dict[str, uuid.UUID],
        findings: list[Finding],
    ) -> None:
        """Append LLM-review findings, deduped against the deterministic ones."""
        if not self._settings.ai_scan_enabled:
            return
        reviewer = AIReviewScanner(self._ai_settings or self._settings)
        if not reviewer.available:
            return

        # Don't re-review 'other' files; focus on DevOps artifacts.
        paths = [
            f.path for f in discovered_files if f.category is not FileCategory.OTHER
        ]
        # (file_id, line) already reported by the rules - skip AI echoes of them.
        occupied = {
            (f.file_id, f.line_number) for f in findings if f.line_number is not None
        }
        added = 0
        for rule_finding in reviewer.analyze_repo(repo_root, paths):
            file_id = file_id_by_path.get(rule_finding.file_path or "")
            if (
                rule_finding.line_number is not None
                and (file_id, rule_finding.line_number) in occupied
            ):
                continue
            findings.append(self._to_finding(scan_id, file_id, rule_finding))
            added += 1
        logger.info(
            "ai_review_completed",
            scan_id=str(scan_id),
            files_reviewed=len(paths),
            findings_added=added,
        )

    @staticmethod
    def _read_file_content(path: Path) -> str | None:
        """Return text content for a small text file, else None (UI code viewer)."""
        try:
            if path.stat().st_size > _MAX_CONTENT_BYTES:
                return None
            data = path.read_bytes()
        except OSError:
            return None
        if b"\x00" in data[:8192]:  # binary
            return None
        return data.decode("utf-8", errors="replace")

    @staticmethod
    def _to_finding(
        scan_id: uuid.UUID,
        file_id: uuid.UUID | None,
        rule_finding: RuleFinding,
    ) -> Finding:
        # Findings from template/sample env files and test/example/docs paths are
        # capped to LOW across every scanner so they never surface as HIGH/MEDIUM
        # production blockers (the false-positive review then sweeps them).
        rule_finding = downrank_if_low_signal(rule_finding)
        return Finding(
            id=uuid.uuid4(),
            scan_id=scan_id,
            file_id=file_id,
            category=rule_finding.category,
            severity=rule_finding.severity,
            confidence=rule_finding.confidence,
            title=rule_finding.title,
            description=rule_finding.description,
            evidence=rule_finding.evidence,
            recommendation=rule_finding.recommendation,
            line_number=rule_finding.line_number,
            rule_id=rule_finding.rule_id,
            scanner=rule_finding.scanner,
        )

    # -- ingestion -----------------------------------------------------------

    async def create_zip_scan(
        self,
        *,
        filename: str | None,
        upload_stream: BinaryIO,
    ) -> Scan:
        """Create a PENDING ZIP scan and persist the upload into its workspace.

        This is the request-side half of ingestion: it validates and stores the
        upload but does NOT extract or scan it (that is `run_zip_pipeline`, which
        may run in a worker). The workspace is intentionally left in place for the
        pipeline to consume and clean up.
        """
        display_name = self._safe_display_name(filename)
        self._validate_extension(filename)

        scan = Scan(
            id=uuid.uuid4(),
            repository_name=display_name,
            source_type=SourceType.ZIP,
            status=ScanStatus.PENDING,
        )
        self._session.add(scan)
        await self._session.commit()

        scan_id = scan.id
        workspace = self._workspaces.create(scan_id)
        try:
            self._save_upload(upload_stream, workspace.upload_path)
        except AppError as exc:
            self._workspaces.destroy(workspace)
            await self._fail_scan(scan_id, exc.message)
            raise
        except Exception:
            self._workspaces.destroy(workspace)
            await self._fail_scan(scan_id, "Internal error saving upload.")
            raise
        return scan

    async def run_zip_pipeline(self, scan_id: uuid.UUID) -> tuple[Scan, int]:
        """Extract and scan a previously-created ZIP scan's upload.

        Reads the upload saved by `create_zip_scan` from the (shared) workspace,
        runs the full pipeline, and always removes the workspace afterwards. Safe
        to run in a Celery worker.
        """
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")
        workspace = self._workspaces.get(scan_id)
        try:
            scan.status = ScanStatus.RUNNING
            scan.started_at = _utcnow()
            await self._session.commit()

            self._extractor.extract(workspace.upload_path, workspace.repo_path)
            file_count = await self._process_repo(scan, scan_id, workspace)
            return scan, file_count
        except AppError as exc:
            await self._fail_scan(scan_id, exc.message)
            raise
        except ArchiveValidationError as exc:
            await self._fail_scan(scan_id, str(exc))
            raise InvalidArchiveError(str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 - record unexpected failures too
            logger.error("scan_failed", scan_id=str(scan_id), error=str(exc))
            await self._fail_scan(scan_id, "Internal error during ingestion.")
            raise
        finally:
            self._workspaces.destroy(workspace)

    async def ingest_zip_upload(
        self,
        *,
        filename: str | None,
        upload_stream: BinaryIO,
    ) -> tuple[Scan, int]:
        """Synchronously ingest an uploaded ZIP: create the scan then run it."""
        scan = await self.create_zip_scan(filename=filename, upload_stream=upload_stream)
        return await self.run_zip_pipeline(scan.id)

    async def create_git_scan(
        self,
        *,
        repository_url: str,
        ref: str | None = None,
    ) -> Scan:
        """Validate a git URL and create a PENDING git scan (no clone yet).

        The clone and scan happen in `run_git_pipeline` (possibly on a worker),
        which receives the URL/ref explicitly.
        """
        if not self._settings.git_ingestion_enabled:
            raise GitIngestionDisabledError("Git repository ingestion is disabled.")

        # Validate the URL up front so a bad request never creates a scan row.
        try:
            self._cloner.validate_url(repository_url)
        except GitCloneError as exc:
            raise InvalidGitRepoError(str(exc)) from exc

        scan = Scan(
            id=uuid.uuid4(),
            repository_name=self._cloner.repo_name_from_url(repository_url),
            source_type=SourceType.GIT,
            status=ScanStatus.PENDING,
        )
        self._session.add(scan)
        await self._session.commit()
        return scan

    async def run_git_pipeline(
        self, scan_id: uuid.UUID, repository_url: str, ref: str | None = None
    ) -> tuple[Scan, int]:
        """Clone a previously-created git scan's repository and run the pipeline.

        A hardened shallow clone populates an isolated workspace, which is always
        removed afterwards. Safe to run in a Celery worker; repository code is
        never executed.
        """
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")
        workspace = self._workspaces.create(scan_id)
        try:
            scan.status = ScanStatus.RUNNING
            scan.started_at = _utcnow()
            await self._session.commit()

            self._cloner.clone(repository_url, ref, workspace.repo_path)
            file_count = await self._process_repo(scan, scan_id, workspace)

            logger.info("git_scan_ingested", scan_id=str(scan_id), url_host_only=True)
            return scan, file_count
        except AppError as exc:
            await self._fail_scan(scan_id, exc.message)
            raise
        except GitCloneError as exc:
            await self._fail_scan(scan_id, str(exc))
            raise InvalidGitRepoError(str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 - record unexpected failures too
            logger.error("scan_failed", scan_id=str(scan_id), error=str(exc))
            await self._fail_scan(scan_id, "Internal error during ingestion.")
            raise
        finally:
            self._workspaces.destroy(workspace)

    async def ingest_git_repo(
        self,
        *,
        repository_url: str,
        ref: str | None = None,
    ) -> tuple[Scan, int]:
        """Synchronously clone and scan a git repository: create then run."""
        scan = await self.create_git_scan(repository_url=repository_url, ref=ref)
        return await self.run_git_pipeline(scan.id, repository_url, ref)

    async def _process_repo(
        self, scan: Scan, scan_id: uuid.UUID, workspace: Workspace
    ) -> int:
        """Discover, index, scan and finalise a materialised repository.

        Shared by ZIP and git ingestion: by the time this runs the repository
        contents already exist under ``workspace.repo_path``. Returns the number
        of discovered files.
        """
        discovery = self._discovery.discover(workspace.repo_path)

        file_id_by_path: dict[str, uuid.UUID] = {}
        repo_files: list[RepositoryFile] = []
        for item in discovery.files:
            file_id = uuid.uuid4()
            file_id_by_path[item.path] = file_id
            repo_files.append(
                RepositoryFile(
                    id=file_id,
                    scan_id=scan.id,
                    path=item.path,
                    file_type=item.detected_type,
                    size=item.size,
                    checksum=item.checksum,
                    content=self._read_file_content(workspace.repo_path / item.path),
                )
            )
        self._session.add_all(repo_files)

        # Apply any runtime overrides (e.g. a switched LLM model) for the AI pass.
        self._ai_settings = await resolve_settings(self._session, self._settings)

        # Run deterministic scanners while the workspace still exists.
        findings = self._run_scanners(
            workspace.repo_path, discovery.files, scan.id, file_id_by_path
        )
        self._session.add_all(findings)

        # Extract the cross-stack entity index for later correlation.
        scan.correlation_index = CorrelationExtractor().extract(
            workspace.repo_path,
            [(f.path, f.detected_type) for f in discovery.files],
        )

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = _utcnow()
        await self._session.commit()

        logger.info(
            "scan_completed",
            scan_id=str(scan_id),
            files=len(discovery.files),
            findings=len(findings),
        )
        return len(discovery.files)

    # -- internals -----------------------------------------------------------

    async def _fail_scan(self, scan_id: uuid.UUID, message: str) -> None:
        # Roll back any half-applied unit of work before recording the failure,
        # so the failed-status update commits cleanly on its own.
        await self._session.rollback()
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = ScanStatus.FAILED
        scan.completed_at = _utcnow()
        scan.error_message = message[:2000]
        await self._session.commit()

    def _validate_extension(self, filename: str | None) -> None:
        allowed = self._settings.allowed_upload_extensions_set
        suffix = Path(filename).suffix.lower() if filename else ""
        if suffix not in allowed:
            raise UnsupportedArchiveError(
                f"Unsupported file type '{suffix or 'unknown'}'. "
                f"Allowed: {', '.join(sorted(allowed))}."
            )

    @staticmethod
    def _safe_display_name(filename: str | None) -> str:
        # Use only the base name and strip the archive suffix; never used as a path.
        if not filename:
            return "repository"
        base = Path(filename).name
        stem = base[: -len(Path(base).suffix)] if Path(base).suffix else base
        return stem.strip() or "repository"

    def _save_upload(self, stream: BinaryIO, dest: Path) -> int:
        """Stream the upload to disk, enforcing the maximum size."""
        limit = self._settings.max_upload_size_bytes
        total = 0
        stream.seek(0)
        with dest.open("wb") as out:
            while True:
                chunk = stream.read(_UPLOAD_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise PayloadTooLargeError(
                        f"Upload exceeds the maximum size of "
                        f"{self._settings.max_upload_size_mb} MB."
                    )
                out.write(chunk)
        return total
