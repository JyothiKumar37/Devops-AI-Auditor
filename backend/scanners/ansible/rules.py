"""Deterministic Ansible rule engine.

Line/regex-based checks for the highest-signal Ansible hazards: TLS-verification
bypasses, world-writable file modes, plaintext secrets in variables, insecure
(http) download URLs, non-reproducible ``state: latest`` installs, piping a
remote download into a shell, and raw ``shell``/``command`` usage where a module
is preferable.

Playbooks, roles and vars files are all YAML, so a line-based engine matches the
key-oriented structure well without a full parse. No playbook is ever executed -
the text is only read. Secret *values* are masked and never emitted; the
dedicated secret scanner remains the authority on secret detection.
"""

from __future__ import annotations

import re

from models.enums import Confidence, FindingCategory, Severity
from scanners.finding import RuleFinding

SCANNER = "ansible-rules"

_MAX_EVIDENCE = 160

# `shell:` / `command:` module used as a task key (optionally FQCN-prefixed).
_SHELL_MODULE = re.compile(
    r"^(?:-\s+)?(?:ansible\.builtin\.|ansible\.legacy\.)?(?:shell|command)\s*:"
)
# TLS certificate verification disabled.
_VALIDATE_CERTS = re.compile(r"\bvalidate_certs\s*:\s*(?:no|false)\b", re.IGNORECASE)
# World-writable file mode, or chmod 777 inside a shell/command.
_MODE_777 = re.compile(r"\bmode\s*:\s*['\"]?0?777\b")
_CHMOD_777 = re.compile(r"\bchmod\s+(?:-\S+\s+)*0?777\b")
# Secret-bearing variable key with a literal value.
_SECRET_KEY = re.compile(
    r"^(?:-\s+)?['\"]?(?P<key>[\w]*(?:password|passwd|secret|token|"
    r"api_?key|access_?key|secret_?key)[\w]*)['\"]?\s*:\s*(?P<val>.*)$",
    re.IGNORECASE,
)
# Insecure (plaintext http) URL, excluding loopback/local addresses.
_INSECURE_URL = re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)\S+")
# Non-reproducible "install the newest version" package state.
_STATE_LATEST = re.compile(r"\bstate\s*:\s*['\"]?latest\b")
# Piping a network download straight into a shell interpreter.
_PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b", re.IGNORECASE
)


_META: dict[str, tuple[FindingCategory, Severity, Confidence, str, str, str]] = {
    "ANS001": (
        FindingCategory.BEST_PRACTICE,
        Severity.LOW,
        Confidence.MEDIUM,
        "Raw 'shell'/'command' module used",
        "Using the raw shell/command modules bypasses Ansible's idempotent, "
        "purpose-built modules and, with templated input, risks command "
        "injection.",
        "Prefer a dedicated module (package, copy, template, ...). If shell is "
        "unavoidable, avoid interpolating untrusted variables.",
    ),
    "ANS002": (
        FindingCategory.SECURITY,
        Severity.HIGH,
        Confidence.HIGH,
        "TLS certificate verification disabled",
        "'validate_certs: no' disables certificate verification, exposing the "
        "connection to man-in-the-middle interception.",
        "Remove 'validate_certs: no' and fix the underlying certificate trust "
        "instead of disabling verification.",
    ),
    "ANS003": (
        FindingCategory.SECURITY,
        Severity.MEDIUM,
        Confidence.HIGH,
        "World-writable permissions (777)",
        "A mode of 777 grants read, write and execute to every local user, "
        "allowing tampering by any account on the host.",
        "Grant the least privilege required (e.g. 0640/0750) instead of 777.",
    ),
    "ANS004": (
        FindingCategory.SECURITY,
        Severity.HIGH,
        Confidence.MEDIUM,
        "Plaintext secret in a variable",
        "A secret-bearing variable is assigned a literal value in plain text, so "
        "the credential is committed to source control.",
        "Store secrets with Ansible Vault or an external secrets manager and "
        "reference them via a variable, never a literal.",
    ),
    "ANS005": (
        FindingCategory.SECURITY,
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "Insecure (http) URL",
        "Fetching over plaintext http exposes the transfer to interception and "
        "tampering in transit.",
        "Use an https URL so the download is authenticated and encrypted.",
    ),
    "ANS006": (
        FindingCategory.BEST_PRACTICE,
        Severity.LOW,
        Confidence.HIGH,
        "Non-reproducible 'state: latest'",
        "Installing 'state: latest' makes runs non-deterministic: the version "
        "installed depends on when the play is executed.",
        "Pin an explicit version (or use 'state: present') for reproducible runs.",
    ),
    "ANS007": (
        FindingCategory.SECURITY,
        Severity.HIGH,
        Confidence.HIGH,
        "Remote script piped directly into a shell",
        "Downloading a script and piping it straight into a shell executes "
        "unverified remote code; a tampered endpoint yields arbitrary command "
        "execution on the managed host.",
        "Download to a file, verify it (checksum/signature), then run it "
        "explicitly.",
    ),
}


def _truncate(text: str) -> str:
    text = text.strip()
    return text if len(text) <= _MAX_EVIDENCE else text[: _MAX_EVIDENCE - 1] + "…"


def _make(rule_id: str, file_path: str, line: int | None, evidence: str | None) -> RuleFinding:
    category, severity, confidence, title, description, recommendation = _META[rule_id]
    return RuleFinding(
        rule_id=rule_id,
        scanner=SCANNER,
        category=category,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        recommendation=recommendation,
        file_path=file_path,
        line_number=line,
        evidence=_truncate(evidence) if evidence else None,
    )


def _is_literal_secret(value: str) -> bool:
    """True if `value` is a plaintext secret (not templated, vaulted or empty)."""
    val = value.strip().strip("'\"").strip()
    if not val:
        return False
    if val.startswith("{{") or val.startswith("!vault") or "$ANSIBLE_VAULT" in val:
        return False
    # A bare variable reference or lookup is not a literal secret.
    return "{{" not in val


def analyze(text: str, file_path: str) -> list[RuleFinding]:
    """Analyse Ansible YAML text and return findings (pure, IO-free)."""
    findings: list[RuleFinding] = []

    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if _SHELL_MODULE.match(line):
            findings.append(_make("ANS001", file_path, index, line))
        if _VALIDATE_CERTS.search(line):
            findings.append(_make("ANS002", file_path, index, line))
        if _MODE_777.search(line) or _CHMOD_777.search(line):
            findings.append(_make("ANS003", file_path, index, line))
        if _STATE_LATEST.search(line):
            findings.append(_make("ANS006", file_path, index, line))
        if _PIPE_TO_SHELL.search(line):
            findings.append(_make("ANS007", file_path, index, line))
        if _INSECURE_URL.search(line):
            findings.append(_make("ANS005", file_path, index, line))

        secret = _SECRET_KEY.match(line)
        if secret:
            key = secret.group("key")
            # A "*_file"/"*_path" key points at a file, not the secret itself.
            if not key.lower().endswith(("file", "path")) and _is_literal_secret(
                secret.group("val")
            ):
                findings.append(_make("ANS004", file_path, index, f"{key}: <redacted>"))

    return findings
