"""Optional external Kubernetes tool adapters.

kubeconform (schema validation), kube-linter (lint) and Trivy config scanning are
integrated when their binaries are available on PATH. Each adapter exposes a pure
`parse_*` function (unit-testable without the binary) and a `run` that shells out
and never raises. When a tool is absent, no findings are contributed and the
deterministic engine remains the primary source.
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


# --- kubeconform ------------------------------------------------------------

KUBECONFORM = "kubeconform"


def kubeconform_available() -> bool:
    return _which(KUBECONFORM)


def parse_kubeconform_json(output: str, file_path: str) -> list[RuleFinding]:
    """Map kubeconform JSON into schema-validation findings."""
    try:
        report = json.loads(output or "{}")
    except json.JSONDecodeError:
        return []
    findings: list[RuleFinding] = []
    for resource in report.get("resources", []) or []:
        status = str(resource.get("status", ""))
        if status in {"statusInvalid", "statusError"}:
            message = str(resource.get("msg", "schema validation failed"))
            findings.append(
                RuleFinding(
                    rule_id="kubeconform",
                    scanner="kubeconform",
                    category=FindingCategory.CONFIGURATION,
                    severity=Severity.HIGH if status == "statusInvalid" else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title="Manifest fails schema validation",
                    description=message,
                    recommendation="Fix the manifest to conform to the Kubernetes schema.",
                    file_path=file_path,
                    line_number=None,
                    evidence=str(resource.get("kind", "")),
                )
            )
    return findings


def run_kubeconform(path: Path, file_path: str, *, timeout: int = 120) -> list[RuleFinding]:
    if not kubeconform_available():
        return []
    try:
        completed = subprocess.run(  # noqa: S603
            [KUBECONFORM, "-summary", "-output", "json", str(path)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("kubeconform_failed", error=str(exc))
        return []
    return parse_kubeconform_json(completed.stdout, file_path)


# --- kube-linter ------------------------------------------------------------

KUBELINTER = "kube-linter"

_KL_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
}


def kubelinter_available() -> bool:
    return _which(KUBELINTER)


def parse_kubelinter_json(output: str) -> list[RuleFinding]:
    """Map kube-linter JSON into findings (file path taken from each report)."""
    try:
        report = json.loads(output or "{}")
    except json.JSONDecodeError:
        return []
    findings: list[RuleFinding] = []
    for item in report.get("Reports", []) or []:
        diagnostic = item.get("Diagnostic", {}) or {}
        obj = item.get("Object", {}) or {}
        metadata = obj.get("Metadata", {}) or {}
        check = str(item.get("Check", "kube-linter"))
        message = str(diagnostic.get("Message", "")).strip()
        file_path = str(metadata.get("FilePath", "")) or "unknown"
        findings.append(
            RuleFinding(
                rule_id=check,
                scanner="kube-linter",
                category=FindingCategory.RELIABILITY,
                severity=_KL_SEVERITY.get(str(item.get("Severity", "warning")).lower(),
                                          Severity.MEDIUM),
                confidence=Confidence.HIGH,
                title=message[:120] or check,
                description=message,
                recommendation=f"See kube-linter check '{check}'.",
                file_path=file_path,
                line_number=None,
                evidence=check,
            )
        )
    return findings


def run_kubelinter(repo_root: Path, *, timeout: int = 120) -> list[RuleFinding]:
    if not kubelinter_available():
        return []
    try:
        completed = subprocess.run(  # noqa: S603
            [KUBELINTER, "lint", "--format", "json", str(repo_root)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("kubelinter_failed", error=str(exc))
        return []
    return parse_kubelinter_json(completed.stdout)


# --- trivy config -----------------------------------------------------------

TRIVY = "trivy"

_TRIVY_SEVERITY = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "UNKNOWN": Severity.INFO,
}


def trivy_available() -> bool:
    return _which(TRIVY)


def parse_trivy_config_json(output: str) -> list[RuleFinding]:
    """Map `trivy config` JSON misconfigurations into findings."""
    try:
        report = json.loads(output or "{}")
    except json.JSONDecodeError:
        return []
    findings: list[RuleFinding] = []
    for result in report.get("Results", []) or []:
        target = str(result.get("Target", ""))
        for misconf in result.get("Misconfigurations", []) or []:
            sev = str(misconf.get("Severity", "UNKNOWN")).upper()
            findings.append(
                RuleFinding(
                    rule_id=str(misconf.get("ID", "trivy")),
                    scanner="trivy",
                    category=FindingCategory.SECURITY,
                    severity=_TRIVY_SEVERITY.get(sev, Severity.INFO),
                    confidence=Confidence.HIGH,
                    title=str(misconf.get("Title", "Misconfiguration"))[:120],
                    description=str(misconf.get("Description", "")),
                    recommendation=str(misconf.get("Resolution", "")),
                    file_path=target,
                    line_number=None,
                    evidence=str(misconf.get("ID", "")),
                )
            )
    return findings


def run_trivy_config(repo_root: Path, *, timeout: int = 120) -> list[RuleFinding]:
    if not trivy_available():
        return []
    try:
        completed = subprocess.run(  # noqa: S603
            [TRIVY, "config", "--quiet", "--format", "json", str(repo_root)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("trivy_config_failed", error=str(exc))
        return []
    return parse_trivy_config_json(completed.stdout)
