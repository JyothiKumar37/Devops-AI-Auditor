"""Deterministic Jenkinsfile analyzer.

Jenkinsfiles are Groovy, not a declarative data format, so this analyzer works on
the source text line-by-line with conservative patterns. It only reports what the
text actually contains (no behavioural inference).
"""

from __future__ import annotations

import re

from models.enums import Confidence, FindingCategory, Severity
from scanners.cicd.common import (
    AWS_ACCESS_KEY_RE,
    CURL_PIPE_SH_RE,
    INSECURE_TLS_RE,
    PRIVATE_KEY_RE,
    Emitter,
    RuleSpec,
)
from scanners.finding import RuleFinding

SCANNER_NAME = "jenkins-rules"

C = FindingCategory
S = Severity
CF = Confidence

RULES: dict[str, RuleSpec] = {
    "JNK001": RuleSpec(C.SECRETS, S.CRITICAL, CF.HIGH,
        "Hardcoded credential in Jenkinsfile",
        "Use the Jenkins credentials store (credentials()/withCredentials), not literals."),
    "JNK002": RuleSpec(C.SECURITY, S.HIGH, CF.MEDIUM,
        "Unsafe parameter/variable interpolation in shell",
        "Use single-quoted sh with env vars, not Groovy interpolation of untrusted input."),
    "JNK003": RuleSpec(C.SECRETS, S.MEDIUM, CF.MEDIUM,
        "Secret exposed in build log",
        "Do not echo credentials/secrets."),
    "JNK004": RuleSpec(C.SECURITY, S.MEDIUM, CF.MEDIUM,
        "Elevated privileges in shell (sudo)",
        "Avoid sudo in CI; grant the agent only the permissions it needs."),
    "JNK005": RuleSpec(C.SECURITY, S.MEDIUM, CF.HIGH,
        "Remote script piped into a shell",
        "Download, verify, then execute; avoid curl | sh."),
    "JNK006": RuleSpec(C.SECURITY, S.MEDIUM, CF.HIGH,
        "TLS verification disabled",
        "Do not disable certificate verification."),
}

_CRED_ASSIGN_RE = re.compile(
    r"[A-Za-z_]*(password|passwd|secret|token|api[_-]?key|access[_-]?key)\b\s*[:=]\s*"
    r'["\']([^"\'$][^"\']*)["\']',
    re.IGNORECASE,
)
_URL_BASIC_AUTH_RE = re.compile(r"https?://[^\s:@/]+:[^\s:@/]+@", re.IGNORECASE)
# sh with a double-quoted string containing Groovy interpolation (${...}).
# sh with a double-quoted string (single or triple) that interpolates ${...}.
_UNSAFE_SH_RE = re.compile(r'\bsh\b\s*\(?\s*"+[^"]*\$\{', re.IGNORECASE)
_ECHO_SECRET_RE = re.compile(
    r"\b(echo|println|print)\b[^\n]*\$\{?[A-Za-z_.]*"
    r"(PASSWORD|SECRET|TOKEN|APIKEY|API_KEY|CREDENTIAL)",
    re.IGNORECASE,
)
_SUDO_RE = re.compile(r"\bsudo\b")
_SAFE_MARKERS = ("credentials(", "withCredentials", "credentialsId")


def analyze_jenkinsfile(file_path: str, text: str) -> list[RuleFinding]:
    emit = Emitter(RULES, SCANNER_NAME, file_path)
    in_block_comment = False
    for index, line in enumerate(text.splitlines()):
        line_no = index + 1
        stripped = line.strip()

        # Skip Groovy comments so commented-out code is not reported as a finding.
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("/*"):
            if "*/" not in stripped:
                in_block_comment = True
            continue
        if stripped.startswith("//") or stripped.startswith("*"):
            continue

        has_safe_marker = any(marker in line for marker in _SAFE_MARKERS)

        if PRIVATE_KEY_RE.search(line):
            emit.add("JNK001", description="A private key is embedded in the Jenkinsfile.",
                     line=line_no, evidence="-----BEGIN PRIVATE KEY----- (redacted)")
        elif AWS_ACCESS_KEY_RE.search(line):
            emit.add("JNK001", description="An AWS access key ID is hardcoded.",
                     line=line_no, evidence="AKIA<redacted>")
        elif _URL_BASIC_AUTH_RE.search(line) and not has_safe_marker:
            emit.add("JNK001", description="A URL embeds basic-auth credentials.",
                     line=line_no, evidence="https://****:****@...")
        elif _CRED_ASSIGN_RE.search(line) and not has_safe_marker:
            emit.add("JNK001", description="A credential is assigned a literal value.",
                     line=line_no, evidence="<redacted>")

        if _UNSAFE_SH_RE.search(line):
            emit.add("JNK002",
                     description="A double-quoted sh command interpolates a Groovy variable "
                     "(possible command injection).",
                     line=line_no, evidence=line.strip()[:80])
        if _ECHO_SECRET_RE.search(line):
            emit.add("JNK003", description="A secret/credential is echoed to the log.",
                     line=line_no)
        if _SUDO_RE.search(line):
            emit.add("JNK004", description="sudo is used in a build step.", line=line_no)
        if CURL_PIPE_SH_RE.search(line):
            emit.add("JNK005", description="A remote script is piped into a shell.", line=line_no)
        if INSECURE_TLS_RE.search(line):
            emit.add("JNK006", description="TLS certificate verification is disabled.",
                     line=line_no)

    return emit.findings
