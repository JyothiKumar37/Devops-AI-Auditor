"""The Docker Compose scanner.

Validates Compose YAML syntax first, then runs the deterministic rule engine.
A syntax error yields a single DCMP000 finding rather than crashing the scan.
"""

from __future__ import annotations

from pathlib import Path

from core.config import Settings
from core.logging import get_logger
from models.enums import ScannerType
from scanners.compose.parser import ComposeSyntaxError, load_compose
from scanners.compose.rules import analyze as run_rules
from scanners.compose.rules import make_syntax_finding
from scanners.finding import RuleFinding

logger = get_logger(__name__)


class DockerComposeScanner:
    """Analyses Docker Compose files and returns findings."""

    scanner_type = ScannerType.DOCKER_COMPOSE

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings

    def analyze_text(self, text: str, file_path: str) -> list[RuleFinding]:
        """Validate then analyse Compose text (IO-free; used by tests)."""
        try:
            root = load_compose(text)
        except ComposeSyntaxError as exc:
            return [make_syntax_finding(file_path, exc.message, exc.line)]
        return run_rules(root, file_path=file_path)

    def analyze_file(self, repo_root: Path, relative_path: str) -> list[RuleFinding]:
        """Analyse a Compose file on disk."""
        abs_path = repo_root / relative_path
        try:
            text = abs_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.warning("compose_read_failed", path=relative_path, error=str(exc))
            return []
        return self.analyze_text(text, relative_path)
