"""The Secrets Detection Agent.

Scans the working tree (all text files) for secrets using deterministic
detectors, and optionally augments with Gitleaks. Every finding carries only a
MASKED value - raw secrets are never returned or stored. Files are read as data
only; repository code is never executed.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from core.config import Settings
from core.logging import get_logger
from models.enums import FindingCategory, Severity
from scanners.finding import RuleFinding
from scanners.low_signal import downrank, is_low_signal_path
from scanners.secrets import gitleaks
from scanners.secrets.detectors import (
    DETECTORS,
    PRIVATE_KEY_RE,
    RULES,
    find_generic_credentials,
    find_high_entropy_tokens,
)
from scanners.secrets.masking import mask_secret

logger = get_logger(__name__)

_MAX_FILE_BYTES = 5 * 1024 * 1024
_BINARY_SNIFF = 8192

# A commented-out line is code the author disabled, not a live secret. The
# low-precision generic (SEC010) and high-entropy (SEC011) detectors skip such
# lines so example/placeholder credentials in comments are not reported. Real
# structured secrets (AWS keys, private keys, DB URLs, provider tokens) are
# still detected even inside comments, since committing those is a genuine leak.
_COMMENT_PREFIXES = ("#", "//", "/*", "*", "<!--", "--", ";", "'''", '"""')


def _is_comment_line(raw_line: str) -> bool:
    return raw_line.strip().startswith(_COMMENT_PREFIXES)

_LOCKFILE_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "cargo.lock",
    "composer.lock", "gemfile.lock", "poetry.lock", "pipfile.lock",
}


class SecretScanner:
    """Detects hardcoded secrets across a repository, emitting masked findings."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings

    # -- pure detection (used by tests) --------------------------------------

    def scan_text(self, file_path: str, text: str) -> list[RuleFinding]:
        """Detect secrets in a single file's text. Returns masked findings."""
        candidates: list[RuleFinding] = []
        is_lockfile = PurePosixPath(file_path).name.lower() in _LOCKFILE_NAMES

        # Multi-line private keys.
        for match in PRIVATE_KEY_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            candidates.append(
                self._finding("SEC007", file_path, line, "-----BEGIN PRIVATE KEY----- (redacted)")
            )

        for index, raw_line in enumerate(text.splitlines()):
            line_no = index + 1
            structured_values: set[str] = set()
            is_comment = _is_comment_line(raw_line)

            for detector in DETECTORS:
                for match in detector.pattern.finditer(raw_line):
                    value = match.group(detector.value_group)
                    if not value:
                        continue
                    structured_values.add(value)
                    if detector.rule_id == "SEC009":
                        evidence = match.group(0).replace(value, "****")
                    else:
                        evidence = mask_secret(value)
                    candidates.append(
                        self._finding(detector.rule_id, file_path, line_no, evidence)
                    )

            if not is_comment:
                for _key, value in find_generic_credentials(raw_line):
                    if value in structured_values:
                        continue
                    structured_values.add(value)
                    candidates.append(
                        self._finding("SEC010", file_path, line_no, mask_secret(value))
                    )

            if not is_lockfile and not is_comment:
                for token in find_high_entropy_tokens(raw_line):
                    if token in structured_values:
                        continue
                    candidates.append(
                        self._finding("SEC011", file_path, line_no, mask_secret(token))
                    )

        findings = _dedupe(candidates)
        if is_low_signal_path(file_path):
            findings = [downrank(f) for f in findings]
        return findings

    # -- repository scanning -------------------------------------------------

    def analyze_repo(
        self,
        repo_root: Path,
        relative_paths: list[str],
        scan_history: bool | None = None,
    ) -> list[RuleFinding]:
        """Scan every readable text file, then optionally run Gitleaks."""
        findings: list[RuleFinding] = []
        for rel in relative_paths:
            text = self._read_text(repo_root / rel)
            if text is None:
                continue
            findings += self.scan_text(rel, text)

        findings += self._run_gitleaks(repo_root, scan_history)
        return findings

    def _run_gitleaks(self, repo_root: Path, scan_history: bool | None) -> list[RuleFinding]:
        settings = self._settings
        if settings is not None and not settings.secrets_enable_gitleaks:
            return []
        if not gitleaks.is_available():
            return []
        if scan_history is None:
            scan_history = bool(settings and settings.secrets_scan_history)
        timeout = settings.external_tool_timeout if settings else 300
        return gitleaks.run(repo_root, scan_history=scan_history, timeout=timeout)

    @staticmethod
    def _read_text(path: Path) -> str | None:
        try:
            if not path.is_file() or path.is_symlink():
                return None
            if path.stat().st_size > _MAX_FILE_BYTES:
                return None
            data = path.read_bytes()
        except OSError:
            return None
        if b"\x00" in data[:_BINARY_SNIFF]:  # binary file
            return None
        return data.decode("utf-8", errors="ignore")

    @staticmethod
    def _finding(rule_id: str, file_path: str, line: int | None, evidence: str) -> RuleFinding:
        rule = RULES[rule_id]
        return RuleFinding(
            rule_id=rule_id,
            scanner="secret-scanner",
            category=FindingCategory.SECRETS,
            severity=rule.severity,
            confidence=rule.confidence,
            title=f"{rule.label} detected",
            description=f"A {rule.label.lower()} appears to be committed in this file.",
            recommendation=rule.remediation,
            file_path=file_path,
            line_number=line,
            evidence=evidence,
        )


def _severity_rank(finding: RuleFinding) -> int:
    return Severity(finding.severity).rank


def _dedupe(candidates: list[RuleFinding]) -> list[RuleFinding]:
    """Collapse duplicates on (line, masked evidence), keeping the most severe."""
    best: dict[tuple[int | None, str | None], RuleFinding] = {}
    for finding in candidates:
        key = (finding.line_number, finding.evidence)
        current = best.get(key)
        if current is None or _severity_rank(finding) > _severity_rank(current):
            best[key] = finding
    return list(best.values())
