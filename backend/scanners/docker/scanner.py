"""The Docker scanner.

Orchestrates the deterministic rule engine (always run) with the optional
Hadolint and Trivy adapters (used only when their binaries are present and, for
Trivy, explicitly enabled). Produces a combined, deterministic-first list of
findings for a Dockerfile.
"""

from __future__ import annotations

from pathlib import Path

from core.config import Settings
from core.logging import get_logger
from models.enums import ScannerType
from scanners.docker import hadolint, trivy
from scanners.docker.parser import Dockerfile, parse_dockerfile
from scanners.docker.rules import analyze as run_rules
from scanners.finding import RuleFinding

logger = get_logger(__name__)

_SPECIAL_IMAGES = {"scratch"}


class DockerScanner:
    """Analyses Dockerfiles and returns findings."""

    scanner_type = ScannerType.DOCKERFILE

    def __init__(self, settings: Settings | None = None) -> None:
        self._enable_hadolint = settings.docker_enable_hadolint if settings else True
        self._enable_trivy = settings.docker_enable_trivy if settings else False
        self._timeout = settings.external_tool_timeout if settings else 120

    def analyze_text(self, text: str, file_path: str) -> list[RuleFinding]:
        """Deterministic, IO-free analysis of Dockerfile text (used by tests)."""
        dockerfile = parse_dockerfile(text)
        return run_rules(dockerfile, file_path=file_path)

    def analyze_file(self, repo_root: Path, relative_path: str) -> list[RuleFinding]:
        """Analyse a Dockerfile on disk, adding tool findings where available."""
        abs_path = repo_root / relative_path
        try:
            text = abs_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.warning("dockerfile_read_failed", path=relative_path, error=str(exc))
            return []

        dockerfile = parse_dockerfile(text)
        findings = run_rules(dockerfile, file_path=relative_path)

        if self._enable_hadolint and hadolint.is_available():
            findings += hadolint.run(abs_path, relative_path, timeout=self._timeout)

        if self._enable_trivy and trivy.is_available():
            findings += self._scan_base_images(dockerfile, relative_path)

        return findings

    def _scan_base_images(self, dockerfile: Dockerfile, file_path: str) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        seen: set[str] = set()
        for from_image in dockerfile.froms:
            image = from_image.image
            if (
                not image
                or image in _SPECIAL_IMAGES
                or image in dockerfile.stage_aliases
                or not (from_image.tag or from_image.digest)
            ):
                continue
            ref = image
            if from_image.tag:
                ref = f"{image}:{from_image.tag}"
            if from_image.digest:
                ref = f"{ref}@{from_image.digest}"
            if ref in seen:
                continue
            seen.add(ref)
            findings += trivy.run(
                ref, file_path, from_image.instruction.line, timeout=self._timeout
            )
        return findings
