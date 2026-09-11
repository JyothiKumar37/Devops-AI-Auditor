"""Optional Hadolint adapter.

Hadolint is a well-established, deterministic Dockerfile linter. When its binary
is available we run it and map its JSON output into `RuleFinding`s. When it is
absent (or fails), we simply contribute no findings - the deterministic rule
engine remains the primary source.
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

SCANNER_NAME = "hadolint"
_BINARY = "hadolint"

_LEVEL_TO_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "style": Severity.INFO,
}


def is_available() -> bool:
    """True if the hadolint binary is on PATH."""
    return shutil.which(_BINARY) is not None


def parse_hadolint_json(output: str, file_path: str) -> list[RuleFinding]:
    """Map Hadolint JSON output into findings (pure; unit-testable)."""
    try:
        entries = json.loads(output or "[]")
    except json.JSONDecodeError:
        return []

    findings: list[RuleFinding] = []
    for entry in entries:
        code = str(entry.get("code", "")) or "HADOLINT"
        level = str(entry.get("level", "warning")).lower()
        message = str(entry.get("message", "")).strip()
        line = entry.get("line")
        findings.append(
            RuleFinding(
                rule_id=code,
                scanner=SCANNER_NAME,
                category=FindingCategory.BEST_PRACTICE,
                severity=_LEVEL_TO_SEVERITY.get(level, Severity.MEDIUM),
                confidence=Confidence.HIGH,
                title=message[:120] or code,
                description=message,
                recommendation=f"See Hadolint rule {code}.",
                file_path=file_path,
                line_number=int(line) if isinstance(line, int) else None,
                evidence=code,
            )
        )
    return findings


def run(dockerfile_path: Path, file_path: str, *, timeout: int = 120) -> list[RuleFinding]:
    """Run hadolint against a file on disk and return findings.

    Never raises: any failure results in an empty list so scanning is resilient.
    """
    if not is_available():
        return []
    try:
        completed = subprocess.run(  # noqa: S603 - fixed binary, no shell
            [_BINARY, "-f", "json", str(dockerfile_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("hadolint_failed", error=str(exc))
        return []

    # Hadolint exits non-zero when it reports issues; stdout still holds JSON.
    return parse_hadolint_json(completed.stdout, file_path)
