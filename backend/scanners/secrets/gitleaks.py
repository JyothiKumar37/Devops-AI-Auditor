"""Optional Gitleaks adapter.

Gitleaks reports the raw secret in its JSON output; this adapter MASKS it before
building a finding so no raw secret is ever persisted. Used only when the binary
is present; otherwise the deterministic detectors are the sole source.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from core.logging import get_logger
from models.enums import Confidence, FindingCategory, Severity
from scanners.finding import RuleFinding
from scanners.secrets.masking import mask_secret

logger = get_logger(__name__)

_BINARY = "gitleaks"


def is_available() -> bool:
    return shutil.which(_BINARY) is not None


def parse_gitleaks_json(output: str) -> list[RuleFinding]:
    """Map Gitleaks JSON into findings, masking the reported secret."""
    try:
        entries = json.loads(output or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(entries, list):
        return []

    findings: list[RuleFinding] = []
    for entry in entries:
        raw_secret = str(entry.get("Secret", "") or entry.get("Match", ""))
        rule = str(entry.get("RuleID", "") or "gitleaks")
        description = str(entry.get("Description", "")).strip() or "Secret detected by Gitleaks"
        file_path = str(entry.get("File", "")).lstrip("./") or "unknown"
        findings.append(
            RuleFinding(
                rule_id="SEC012",
                scanner="gitleaks",
                category=FindingCategory.SECRETS,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title=f"Secret detected by Gitleaks ({rule})",
                description=description,
                recommendation="Rotate the secret and remove it from the repository/history.",
                file_path=file_path,
                line_number=entry.get("StartLine"),
                # Masked - never the raw secret.
                evidence=mask_secret(raw_secret) if raw_secret else None,
            )
        )
    return findings


def run(repo_root: Path, *, scan_history: bool = False, timeout: int = 300) -> list[RuleFinding]:
    """Run Gitleaks over a directory. Never raises."""
    if not is_available():
        return []
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=True) as report:
        cmd = [
            _BINARY, "detect", "--source", str(repo_root),
            "--report-format", "json", "--report-path", report.name, "--no-banner",
        ]
        # Without an explicit request, scan only the working tree (not git log).
        if not (scan_history and (repo_root / ".git").exists()):
            cmd.append("--no-git")
        try:
            subprocess.run(  # noqa: S603 - fixed binary, no shell
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
            report.seek(0)
            return parse_gitleaks_json(report.read())
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("gitleaks_failed", error=str(exc))
            return []
