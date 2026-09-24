"""Deterministic shell-script rule engine.

Regex/line-based checks for the highest-signal shell scripting hazards: piping a
remote download straight into a shell, ``eval`` on dynamic input, destructive
``rm -rf`` against root or an unquoted variable, TLS-verification bypasses on
downloads, world-writable permissions, ``sudo`` inside scripts, and the two
foundational reliability gaps (missing shebang and missing error handling).

No shell is ever executed - the script text is only read. Secret *values* are
detected by the dedicated secret scanner, so they are intentionally not
duplicated here.
"""

from __future__ import annotations

import re

from models.enums import Confidence, FindingCategory, Severity
from scanners.finding import RuleFinding

SCANNER = "shell-rules"

_MAX_EVIDENCE = 160

# --- line-level patterns ----------------------------------------------------
# Piping a network download into a shell interpreter (remote code execution).
_PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b", re.IGNORECASE
)
# eval in command position (start of line or after ; & | ` or $( ).
_EVAL = re.compile(r"(?:^|[;&|`(])\s*eval\b")
# `rm -rf` (flags in any order) and, separately, a dangerous target.
_RM_RF = re.compile(
    r"\brm\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\b"
    r"|\brm\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\b",
    re.IGNORECASE,
)
_RM_ROOT_TARGET = re.compile(r"\s/(?:\s|$|\w|\*)")
_RM_VAR_TARGET = re.compile(r"\"?\$\{?\w+")
# chmod granting world-writable / full permissions.
_CHMOD_777 = re.compile(r"\bchmod\s+(?:-[a-zA-Z]+\s+)*0?777\b")
# Downloads that disable TLS certificate verification.
_CURL_INSECURE = re.compile(r"\bcurl\b[^\n]*\s(?:-k|--insecure)(?:\s|$)")
_WGET_INSECURE = re.compile(r"\bwget\b[^\n]*\s--no-check-certificate\b")
# sudo invoked from within a script.
_SUDO = re.compile(r"\bsudo\s")

# --- file-level patterns ----------------------------------------------------
# Any form of "abort on error": set -e / -eu / -euo / set -o errexit.
_ERREXIT = re.compile(
    r"(?m)^\s*set\s+-[a-zA-Z]*e[a-zA-Z]*\b|^\s*set\s+-o\s+errexit\b"
)


# rule_id -> (category, severity, confidence, title, description, recommendation)
_META: dict[str, tuple[FindingCategory, Severity, Confidence, str, str, str]] = {
    "SH001": (
        FindingCategory.BEST_PRACTICE,
        Severity.LOW,
        Confidence.HIGH,
        "Missing shebang",
        "The script has no '#!' shebang, so the interpreter used depends on how "
        "it is invoked, which is non-portable and error-prone.",
        "Add a shebang as the first line, e.g. '#!/usr/bin/env bash'.",
    ),
    "SH002": (
        FindingCategory.RELIABILITY,
        Severity.MEDIUM,
        Confidence.HIGH,
        "No error handling (missing 'set -e')",
        "The script does not enable errexit, so it continues after a failed "
        "command and can leave the system in a half-applied, inconsistent state.",
        "Add 'set -euo pipefail' near the top to abort on errors, unset "
        "variables and failed pipelines.",
    ),
    "SH003": (
        FindingCategory.SECURITY,
        Severity.HIGH,
        Confidence.HIGH,
        "Remote script piped directly into a shell",
        "Downloading a script and piping it straight into a shell executes "
        "unverified remote code; a compromised or tampered endpoint yields "
        "arbitrary command execution.",
        "Download to a file, verify it (checksum/signature), review it, then "
        "execute it explicitly.",
    ),
    "SH004": (
        FindingCategory.SECURITY,
        Severity.HIGH,
        Confidence.MEDIUM,
        "Use of 'eval'",
        "'eval' executes its arguments as code; with any externally influenced "
        "input this enables command injection.",
        "Avoid 'eval'. Use arrays, parameter expansion or explicit dispatch "
        "instead of evaluating constructed strings.",
    ),
    "SH005": (
        FindingCategory.RELIABILITY,
        Severity.HIGH,
        Confidence.MEDIUM,
        "Dangerous 'rm -rf' target",
        "A recursive force delete targets a root path or an unquoted variable; "
        "if the variable is empty or mis-set this can wipe unintended files.",
        "Quote variables, guard against empty values, and never recursively "
        "delete root or near-root paths.",
    ),
    "SH006": (
        FindingCategory.SECURITY,
        Severity.MEDIUM,
        Confidence.HIGH,
        "World-writable permissions (chmod 777)",
        "'chmod 777' makes a path readable, writable and executable by every "
        "user, allowing tampering by any local account.",
        "Grant the least privilege required (e.g. 750/640) instead of 777.",
    ),
    "SH007": (
        FindingCategory.SECURITY,
        Severity.HIGH,
        Confidence.HIGH,
        "TLS verification disabled on download",
        "Disabling certificate verification (curl -k / wget "
        "--no-check-certificate) exposes the download to man-in-the-middle "
        "tampering.",
        "Remove the insecure flag and fix the underlying certificate trust "
        "instead of bypassing verification.",
    ),
    "SH008": (
        FindingCategory.BEST_PRACTICE,
        Severity.LOW,
        Confidence.HIGH,
        "'sudo' used inside a script",
        "Invoking 'sudo' from within a script mixes privilege escalation with "
        "automation, making the required privileges implicit and harder to audit.",
        "Run the script with the privileges it needs from the caller, or isolate "
        "the specific commands that require elevation.",
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


def analyze(text: str, file_path: str) -> list[RuleFinding]:
    """Analyse shell-script text and return findings (pure, IO-free)."""
    findings: list[RuleFinding] = []
    lines = text.splitlines()

    first_non_empty = next((ln for ln in lines if ln.strip()), "")
    if not first_non_empty.startswith("#!"):
        findings.append(_make("SH001", file_path, 1, None))

    if not _ERREXIT.search(text):
        findings.append(_make("SH002", file_path, 1, None))

    for index, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if _PIPE_TO_SHELL.search(line):
            findings.append(_make("SH003", file_path, index, line))
        if _EVAL.search(line):
            findings.append(_make("SH004", file_path, index, line))
        if _RM_RF.search(line) and (
            _RM_ROOT_TARGET.search(line) or _RM_VAR_TARGET.search(line)
        ):
            findings.append(_make("SH005", file_path, index, line))
        if _CHMOD_777.search(line):
            findings.append(_make("SH006", file_path, index, line))
        if _CURL_INSECURE.search(line) or _WGET_INSECURE.search(line):
            findings.append(_make("SH007", file_path, index, line))
        if _SUDO.search(line):
            findings.append(_make("SH008", file_path, index, line))

    return findings
