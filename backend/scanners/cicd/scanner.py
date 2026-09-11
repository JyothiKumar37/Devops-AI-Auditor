"""The CI/CD scanner.

Dispatches each discovered CI/CD file to the matching platform analyzer
(GitHub Actions, GitLab CI, Jenkins) by its detected type, adds a repo-level
GitHub Actions aggregate (missing tests/scanning), and augments GitHub Actions
findings with actionlint when it is available.
"""

from __future__ import annotations

from pathlib import Path

from core.config import Settings
from core.logging import get_logger
from scanners.cicd import actionlint
from scanners.cicd.github_actions import analyze_github_repo, analyze_github_workflow
from scanners.cicd.gitlab_ci import analyze_gitlab_ci
from scanners.cicd.jenkins import analyze_jenkinsfile
from scanners.finding import RuleFinding

logger = get_logger(__name__)


class CICDScanner:
    """Analyses CI/CD configuration files."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings

    def analyze_texts(self, entries: list[tuple[str, str, str]]) -> list[RuleFinding]:
        """Deterministic analysis of (file_path, detected_type, text) entries."""
        findings: list[RuleFinding] = []
        github_files: list[tuple[str, str]] = []

        for file_path, detected_type, text in entries:
            if detected_type == "github_actions":
                findings += analyze_github_workflow(file_path, text)
                github_files.append((file_path, text))
            elif detected_type == "gitlab_ci":
                findings += analyze_gitlab_ci(file_path, text)
            elif detected_type == "jenkins":
                findings += analyze_jenkinsfile(file_path, text)

        findings += analyze_github_repo(github_files)
        return findings

    def analyze_repo(
        self, repo_root: Path, files: list[tuple[str, str]]
    ) -> list[RuleFinding]:
        """Analyse CI/CD files on disk.

        `files` is a list of (relative_path, detected_type).
        """
        entries: list[tuple[str, str, str]] = []
        for rel, detected_type in files:
            try:
                text = (repo_root / rel).read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                logger.warning("cicd_read_failed", path=rel, error=str(exc))
                continue
            entries.append((rel, detected_type, text))

        findings = self.analyze_texts(entries)
        findings += self._run_actionlint(repo_root, files)
        return findings

    def _run_actionlint(
        self, repo_root: Path, files: list[tuple[str, str]]
    ) -> list[RuleFinding]:
        settings = self._settings
        if settings is not None and not settings.cicd_enable_actionlint:
            return []
        if not actionlint.is_available():
            return []
        timeout = settings.external_tool_timeout if settings else 120
        findings: list[RuleFinding] = []
        for rel, detected_type in files:
            if detected_type == "github_actions":
                findings += actionlint.run(repo_root / rel, rel, timeout=timeout)
        return findings
