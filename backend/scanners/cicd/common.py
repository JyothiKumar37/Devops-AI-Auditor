"""Shared primitives for the CI/CD analyzers.

Each platform analyzer (GitHub Actions, GitLab CI, Jenkins) defines its own rule
registry and uses an `Emitter` bound to that registry to build findings. Common
detection patterns (hardcoded secrets, injection, unsafe downloads) live here so
the platform modules stay focused on structure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from models.enums import Confidence, FindingCategory, Severity
from scanners.finding import RuleFinding


@dataclass(frozen=True, slots=True)
class RuleSpec:
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    title: str
    recommendation: str


class Emitter:
    """Accumulates findings, filling static parts from a rule registry."""

    def __init__(self, registry: dict[str, RuleSpec], scanner_name: str, file_path: str) -> None:
        self._registry = registry
        self._scanner = scanner_name
        self._file_path = file_path
        self.findings: list[RuleFinding] = []

    def add(
        self,
        rule_id: str,
        *,
        description: str,
        line: int | None = None,
        evidence: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
    ) -> None:
        spec = self._registry[rule_id]
        self.findings.append(
            RuleFinding(
                rule_id=rule_id,
                scanner=self._scanner,
                category=spec.category,
                severity=severity or spec.severity,
                confidence=confidence or spec.confidence,
                title=spec.title,
                description=description,
                recommendation=spec.recommendation,
                file_path=self._file_path,
                line_number=line,
                evidence=evidence,
            )
        )


# ---- shared detection patterns ----

# Literal secret assignments: KEY=value / KEY: value / KEY => value with a value
# that is not an obvious reference/placeholder.
SECRET_KEY_RE = re.compile(
    r"(PASSWORD|PASSWD|SECRET|API[_-]?KEY|APIKEY|ACCESS[_-]?KEY|AUTH[_-]?TOKEN|TOKEN|"
    r"PRIVATE[_-]?KEY|PASSPHRASE)",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")

# A remote script piped straight into a shell.
CURL_PIPE_SH_RE = re.compile(
    r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash)\b", re.IGNORECASE
)
# TLS verification disabled.
INSECURE_TLS_RE = re.compile(r"(--insecure|\s-k\b|--no-check-certificate)", re.IGNORECASE)


def is_reference_value(value: str) -> bool:
    """True if a value is a CI variable/secret reference rather than a literal.

    Covers ``${{ secrets.X }}`` (GitHub), ``$VAR`` / ``${VAR}`` (shell/GitLab) and
    Groovy ``${...}`` interpolation.
    """
    stripped = value.strip()
    if not stripped:
        return True
    return stripped.startswith("$") or stripped.startswith("${{")


def looks_like_secret_value(value: str) -> bool:
    """True if the value is a hardcoded secret (AKIA / private key / long token)."""
    return bool(AWS_ACCESS_KEY_RE.search(value) or PRIVATE_KEY_RE.search(value))


def mask(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return f"{value[:2]}****{value[-2:]}"
