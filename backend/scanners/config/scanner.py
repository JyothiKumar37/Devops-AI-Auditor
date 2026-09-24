"""The Config scanner.

Runs the deterministic configuration rule engine over a generic config file
(YAML/JSON/TOML/ini/.env). Read-only: file text is never executed, only analysed.
"""

from __future__ import annotations

from pathlib import Path

from core.config import Settings
from core.logging import get_logger
from models.enums import ScannerType
from scanners.config.rules import analyze as run_rules
from scanners.finding import RuleFinding

logger = get_logger(__name__)


class ConfigScanner:
    """Analyses generic configuration files and returns findings."""

    scanner_type = ScannerType.CONFIG

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings

    def analyze_text(self, text: str, file_path: str) -> list[RuleFinding]:
        """Analyse configuration text (IO-free; used by tests)."""
        return run_rules(text, file_path)

    def analyze_file(self, repo_root: Path, relative_path: str) -> list[RuleFinding]:
        """Analyse a configuration file on disk."""
        abs_path = repo_root / relative_path
        try:
            text = abs_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.warning("config_read_failed", path=relative_path, error=str(exc))
            return []
        return run_rules(text, relative_path)
