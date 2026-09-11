"""Optional actionlint adapter for GitHub Actions workflows.

Used only when the `actionlint` binary is present. Provides a pure JSON parser
(unit-testable) and a runner that never raises.
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

_BINARY = "actionlint"


def is_available() -> bool:
    return shutil.which(_BINARY) is not None


def parse_actionlint_json(output: str, file_path: str) -> list[RuleFinding]:
    """Map actionlint JSON output into findings."""
    try:
        entries = json.loads(output or "[]")
    except json.JSONDecodeError:
        return []
    findings: list[RuleFinding] = []
    for entry in entries:
        kind = str(entry.get("kind", "actionlint"))
        message = str(entry.get("message", "")).strip()
        findings.append(
            RuleFinding(
                rule_id=kind,
                scanner="actionlint",
                category=FindingCategory.CONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title=message[:120] or kind,
                description=message,
                recommendation=f"See actionlint '{kind}' guidance.",
                file_path=file_path,
                line_number=entry.get("line"),
                evidence=kind,
            )
        )
    return findings


def run(path: Path, file_path: str, *, timeout: int = 120) -> list[RuleFinding]:
    if not is_available():
        return []
    try:
        completed = subprocess.run(  # noqa: S603
            [_BINARY, "-format", "{{json .}}", "-no-color", str(path)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("actionlint_failed", error=str(exc))
        return []
    return parse_actionlint_json(completed.stdout, file_path)
