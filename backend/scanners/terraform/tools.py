"""Optional external Terraform tool adapters.

terraform (fmt/validate), TFLint, Checkov and Trivy config scanning are used only
when their binaries are present on PATH. Each has a pure `parse_*` function
(unit-testable) and a `run` that never raises. When absent, the deterministic
engine remains the sole source of findings.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from core.logging import get_logger
from models.enums import Confidence, FindingCategory, Severity
from scanners.finding import RuleFinding

logger = get_logger(__name__)


def _which(binary: str) -> bool:
    return shutil.which(binary) is not None


def terraform_available() -> bool:
    return _which("terraform")


def tflint_available() -> bool:
    return _which("tflint")


def checkov_available() -> bool:
    return _which("checkov")


def trivy_available() -> bool:
    return _which("trivy")


# --- terraform fmt / validate ----------------------------------------------


def parse_fmt_output(output: str) -> list[RuleFinding]:
    """`terraform fmt -check -recursive` prints one unformatted file per line."""
    findings: list[RuleFinding] = []
    for raw in output.splitlines():
        name = raw.strip()
        if not name:
            continue
        findings.append(
            RuleFinding(
                rule_id="terraform_fmt", scanner="terraform",
                category=FindingCategory.BEST_PRACTICE, severity=Severity.INFO,
                confidence=Confidence.HIGH, title="File is not terraform fmt clean",
                description="terraform fmt would reformat this file.",
                recommendation="Run 'terraform fmt'.", file_path=name, line_number=None,
                evidence=None,
            )
        )
    return findings


_TF_DIAG_SEVERITY = {"error": Severity.HIGH, "warning": Severity.MEDIUM}


def parse_validate_json(output: str) -> list[RuleFinding]:
    try:
        report = json.loads(output or "{}")
    except json.JSONDecodeError:
        return []
    findings: list[RuleFinding] = []
    for diag in report.get("diagnostics", []) or []:
        rng = diag.get("range") or {}
        findings.append(
            RuleFinding(
                rule_id="terraform_validate", scanner="terraform",
                category=FindingCategory.CONFIGURATION,
                severity=_TF_DIAG_SEVERITY.get(str(diag.get("severity", "error")), Severity.MEDIUM),
                confidence=Confidence.HIGH,
                title=str(diag.get("summary", "validation issue"))[:120],
                description=str(diag.get("detail", diag.get("summary", ""))),
                recommendation="Resolve the terraform validate diagnostic.",
                file_path=str(rng.get("filename", "")) or "unknown",
                line_number=(rng.get("start") or {}).get("line"),
                evidence=None,
            )
        )
    return findings


# --- TFLint -----------------------------------------------------------------

_TFLINT_SEVERITY = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "notice": Severity.LOW}


def parse_tflint_json(output: str) -> list[RuleFinding]:
    try:
        report = json.loads(output or "{}")
    except json.JSONDecodeError:
        return []
    findings: list[RuleFinding] = []
    for issue in report.get("issues", []) or []:
        rule = issue.get("rule", {}) or {}
        rng = issue.get("range", {}) or {}
        findings.append(
            RuleFinding(
                rule_id=str(rule.get("name", "tflint")), scanner="tflint",
                category=FindingCategory.BEST_PRACTICE,
                severity=_TFLINT_SEVERITY.get(str(rule.get("severity", "warning")).lower(),
                                              Severity.MEDIUM),
                confidence=Confidence.HIGH,
                title=str(issue.get("message", ""))[:120] or str(rule.get("name", "tflint")),
                description=str(issue.get("message", "")),
                recommendation=f"See TFLint rule {rule.get('name', '')}.",
                file_path=str(rng.get("filename", "")) or "unknown",
                line_number=(rng.get("start") or {}).get("line"),
                evidence=str(rule.get("name", "")),
            )
        )
    return findings


# --- Checkov ----------------------------------------------------------------

_CHECKOV_SEVERITY = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW, "INFO": Severity.INFO,
}


def parse_checkov_json(output: str) -> list[RuleFinding]:
    try:
        report = json.loads(output or "{}")
    except json.JSONDecodeError:
        return []
    reports = report if isinstance(report, list) else [report]

    findings: list[RuleFinding] = []
    for entry in reports:
        results = entry.get("results", {}) or {}
        for check in results.get("failed_checks", []) or []:
            line_range = check.get("file_line_range") or []
            severity = str(check.get("severity") or "MEDIUM").upper()
            findings.append(
                RuleFinding(
                    rule_id=str(check.get("check_id", "checkov")), scanner="checkov",
                    category=FindingCategory.SECURITY,
                    severity=_CHECKOV_SEVERITY.get(severity, Severity.MEDIUM),
                    confidence=Confidence.HIGH,
                    title=str(check.get("check_name", ""))[:120],
                    description=str(check.get("check_name", "")),
                    recommendation=str(check.get("guideline") or "Review the Checkov finding."),
                    file_path=str(check.get("file_path", "")).lstrip("/") or "unknown",
                    line_number=line_range[0] if line_range else None,
                    evidence=str(check.get("check_id", "")),
                )
            )
    return findings


# --- runners ----------------------------------------------------------------


def run_fmt(directory: Path, *, timeout: int = 120) -> list[RuleFinding]:
    if not terraform_available():
        return []
    try:
        completed = subprocess.run(  # noqa: S603
            ["terraform", "fmt", "-check", "-recursive", "-no-color", str(directory)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("terraform_fmt_failed", error=str(exc))
        return []
    return parse_fmt_output(completed.stdout)


def run_tflint(directory: Path, *, timeout: int = 120) -> list[RuleFinding]:
    if not tflint_available():
        return []
    try:
        completed = subprocess.run(  # noqa: S603
            ["tflint", "--format", "json", "--chdir", str(directory)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("tflint_failed", error=str(exc))
        return []
    return parse_tflint_json(completed.stdout)


def run_checkov(directory: Path, *, timeout: int = 120) -> list[RuleFinding]:
    if not checkov_available():
        return []
    try:
        completed = subprocess.run(  # noqa: S603
            ["checkov", "-d", str(directory), "-o", "json", "--compact"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("checkov_failed", error=str(exc))
        return []
    return parse_checkov_json(completed.stdout)
