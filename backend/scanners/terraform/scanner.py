"""The Terraform scanner.

Terraform is evaluated per directory (module), so files are grouped by directory
and analysed together - this enables reference and unused-variable analysis
across the files of a module. Optional external tools run per directory when
their binaries are available.
"""

from __future__ import annotations

import os
from pathlib import Path

from core.config import Settings
from core.logging import get_logger
from scanners.finding import RuleFinding
from scanners.terraform import tools
from scanners.terraform.model import TfFile, build_module
from scanners.terraform.parser import LineIndex, TerraformSyntaxError, parse_hcl
from scanners.terraform.rules import Emitter, analyze_module, make_syntax_finding

logger = get_logger(__name__)


class TerraformScanner:
    """Analyses Terraform configurations grouped by module directory."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings

    def analyze_files(self, files: list[tuple[str, str]]) -> list[RuleFinding]:
        """Deterministic, IO-free analysis of (file_path, text) Terraform files."""
        findings: list[RuleFinding] = []
        by_directory: dict[str, list[tuple[str, str]]] = {}
        for file_path, text in files:
            by_directory.setdefault(os.path.dirname(file_path), []).append((file_path, text))

        for directory, group in by_directory.items():
            tf_files: list[TfFile] = []
            for file_path, text in group:
                try:
                    parsed = parse_hcl(text)
                except TerraformSyntaxError as exc:
                    findings.append(make_syntax_finding(file_path, exc.message, exc.line))
                    continue
                tf_files.append(TfFile(file_path, parsed, LineIndex(text)))

            if not tf_files:
                continue
            module = build_module(directory, tf_files)
            emit = Emitter()
            analyze_module(module, emit)
            findings.extend(emit.findings)

        return findings

    def analyze_repo(self, repo_root: Path, relative_paths: list[str]) -> list[RuleFinding]:
        """Analyse Terraform on disk and add external-tool findings when enabled."""
        files: list[tuple[str, str]] = []
        for rel in relative_paths:
            try:
                text = (repo_root / rel).read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                logger.warning("tf_read_failed", path=rel, error=str(exc))
                continue
            files.append((rel, text))

        findings = self.analyze_files(files)
        findings += self._run_external_tools(repo_root, relative_paths)
        return findings

    def _run_external_tools(self, repo_root: Path, relative_paths: list[str]) -> list[RuleFinding]:
        settings = self._settings
        timeout = settings.external_tool_timeout if settings else 120
        directories = {os.path.dirname(rel) for rel in relative_paths}
        findings: list[RuleFinding] = []

        for directory in sorted(directories):
            abs_dir = repo_root / directory
            if (settings is None or settings.tf_enable_terraform) and tools.terraform_available():
                findings += tools.run_fmt(abs_dir, timeout=timeout)
            if (settings is None or settings.tf_enable_tflint) and tools.tflint_available():
                findings += tools.run_tflint(abs_dir, timeout=timeout)
            if (settings is None or settings.tf_enable_checkov) and tools.checkov_available():
                findings += tools.run_checkov(abs_dir, timeout=timeout)
            if settings is not None and settings.tf_enable_trivy and tools.trivy_available():
                findings += _run_trivy_config(abs_dir, timeout=timeout)

        return findings


def _run_trivy_config(directory: Path, *, timeout: int = 120) -> list[RuleFinding]:
    # Reuse the Trivy config runner/parser from the Kubernetes tool adapters.
    from scanners.kubernetes.tools import run_trivy_config

    return run_trivy_config(directory, timeout=timeout)
