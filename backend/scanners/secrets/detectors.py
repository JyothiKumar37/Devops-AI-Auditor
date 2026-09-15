"""Deterministic secret detectors.

Each detector recognises a specific secret type. Detectors return the raw match
only so the scanner can immediately mask it; raw values never travel further.
The generic and high-entropy detectors are deliberately conservative to limit
false positives, and obvious placeholders are ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from models.enums import Confidence, Severity
from scanners.secrets.masking import shannon_entropy


@dataclass(frozen=True, slots=True)
class SecretRule:
    label: str
    severity: Severity
    confidence: Confidence
    remediation: str


_ROTATE = (
    "Revoke/rotate the exposed credential immediately and move it to a secrets "
    "manager or environment variable; purge it from version control history."
)
_S, _CF = Severity, Confidence

RULES: dict[str, SecretRule] = {
    "SEC001": SecretRule("AWS access key ID", _S.CRITICAL, _CF.HIGH, _ROTATE),
    "SEC002": SecretRule("AWS secret access key", _S.CRITICAL, _CF.HIGH, _ROTATE),
    "SEC003": SecretRule("GitHub token", _S.HIGH, _CF.HIGH, _ROTATE),
    "SEC004": SecretRule("Google API key", _S.HIGH, _CF.HIGH, _ROTATE),
    "SEC005": SecretRule("Slack token", _S.HIGH, _CF.HIGH, _ROTATE),
    "SEC006": SecretRule("Stripe secret key", _S.HIGH, _CF.HIGH, _ROTATE),
    "SEC007": SecretRule("Private key", _S.CRITICAL, _CF.HIGH, _ROTATE),
    "SEC008": SecretRule("JSON Web Token", _S.MEDIUM, _CF.MEDIUM, _ROTATE),
    "SEC009": SecretRule("Database connection password", _S.HIGH, _CF.HIGH, _ROTATE),
    "SEC010": SecretRule("Hardcoded credential", _S.MEDIUM, _CF.MEDIUM, _ROTATE),
    "SEC011": SecretRule("High-entropy secret", _S.LOW, _CF.LOW, _ROTATE),
    "SEC012": SecretRule("Secret (Gitleaks)", _S.HIGH, _CF.HIGH, _ROTATE),
}


@dataclass(frozen=True, slots=True)
class Detector:
    rule_id: str
    pattern: re.Pattern[str]
    value_group: int = 0


# Order matters: more specific detectors first so generic/entropy can be skipped
# on lines that already matched a structured secret.
DETECTORS: list[Detector] = [
    Detector("SEC001", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    Detector(
        "SEC002",
        re.compile(
            r"(?i)aws_secret_access_key[\"'\s:=]+[\"']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"
        ),
        value_group=1,
    ),
    Detector("SEC003", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    Detector("SEC003", re.compile(r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b")),
    Detector("SEC004", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Detector("SEC005", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    Detector("SEC006", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    Detector(
        "SEC009",
        re.compile(r"(?i)\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://"
                   r"[^:\s/@]+:([^@\s/]{3,})@"),
        value_group=1,
    ),
    Detector(
        "SEC008",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ),
]

# Private keys span multiple lines; detected against the whole file text.
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |)PRIVATE KEY-----")

_GENERIC_RE = re.compile(
    r"(?i)\b([A-Za-z_]*(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?key|"
    r"auth[_-]?token|token|client[_-]?secret|passphrase))\b\s*[:=]\s*"
    r"[\"']([^\"'\s]{6,})[\"']"
)

# Quoted high-entropy tokens (base64/hex-ish) for the generic entropy detector.
_QUOTED_TOKEN_RE = re.compile(r"[\"']([A-Za-z0-9+/=_\-]{20,})[\"']")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# Structural shapes that are almost never secrets but often trip an entropy
# threshold: URL/route paths, SQL/code identifiers and dotted/camelCase symbols.
# Excluding them removes the dominant class of high-entropy false positives
# (e.g. "/api/v1/manufacturing/work-orders", "hrm_employee_id_idx",
# "formatDouble") without discarding genuinely random tokens (which mix case
# and digits with no path/identifier structure).
_PATH_LIKE_RE = re.compile(r"^/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
_REL_PATH_RE = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+$")
_SNAKE_IDENT_RE = re.compile(r"^[A-Za-z]+(?:_[A-Za-z0-9]+)+$")
_DOTTED_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)+$")
_CAMEL_WORDS_RE = re.compile(r"^[a-z]+(?:[A-Z][a-z]+)+$")


def _looks_like_code_or_path(token: str) -> bool:
    """True if the token is a URL path, SQL/code identifier or dotted symbol."""
    if "/" in token and (_PATH_LIKE_RE.match(token) or _REL_PATH_RE.match(token)):
        return True
    return bool(
        _SNAKE_IDENT_RE.match(token)
        or _DOTTED_RE.match(token)
        or _CAMEL_WORDS_RE.match(token)
    )

_PLACEHOLDER_SUBSTRINGS = (
    "example", "placeholder", "changeme", "change_me", "your_", "yourpassword",
    "dummy", "sample", "redacted", "xxxx", "todo", "notreal", "fake",
)
_ENTROPY_THRESHOLD = 4.0


def is_placeholder(value: str) -> bool:
    """True if a value is obviously not a real secret."""
    lowered = value.lower()
    if value.startswith(("$", "{", "<")) or "${" in value or "{{" in value:
        return True
    return any(marker in lowered for marker in _PLACEHOLDER_SUBSTRINGS)


def find_generic_credentials(line: str) -> list[tuple[str, str]]:
    """Return (key, value) for literal credential assignments (placeholders skipped)."""
    results: list[tuple[str, str]] = []
    for match in _GENERIC_RE.finditer(line):
        value = match.group(2)
        if not is_placeholder(value):
            results.append((match.group(1), value))
    return results


def find_high_entropy_tokens(line: str) -> list[str]:
    """Return quoted high-entropy tokens that are likely secrets."""
    tokens: list[str] = []
    for match in _QUOTED_TOKEN_RE.finditer(line):
        token = match.group(1)
        if is_placeholder(token):
            continue
        # Skip pure-hex checksums/hashes (git SHAs, sha256) - common false positives.
        if _HEX_RE.match(token) and len(token) in (32, 40, 64):
            continue
        # Skip URL paths and code/SQL identifiers - structurally not secrets.
        if _looks_like_code_or_path(token):
            continue
        if shannon_entropy(token) >= _ENTROPY_THRESHOLD:
            tokens.append(token)
    return tokens
