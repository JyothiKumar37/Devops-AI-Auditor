"""The Ansible scanner.

Runs the deterministic Ansible rule engine over a playbook/role/vars file. The
scanner is read-only: playbook text is never executed, only analysed.
"""

from __future__ import annotations

from pathlib import Path

from core.config import Settings
from core.logging import get_logger
from models.enums import ScannerType
from scanners.ansible.rules import analyze as run_rules
from scanners.finding import RuleFinding

logger = get_logger(__name__)


class AnsibleScanner:
    """Analyses Ansible files and returns findings."""

    scanner_type = ScannerType.ANSIBLE

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings

    def analyze_text(self, text: str, file_path: str) -> list[RuleFinding]:
        """Analyse Ansible YAML text (IO-free; used by tests)."""
        return run_rules(text, file_path)

    def analyze_file(self, repo_root: Path, relative_path: str) -> list[RuleFinding]:
        """Analyse an Ansible file on disk."""
        abs_path = repo_root / relative_path
        try:
            text = abs_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.warning("ansible_read_failed", path=relative_path, error=str(exc))
            return []
        return run_rules(text, relative_path)
