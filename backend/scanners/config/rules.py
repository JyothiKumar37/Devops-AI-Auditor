"""Deterministic configuration-file rule engine.

Generic config files (YAML, JSON, TOML, ini, .env) share a key/value shape, so a
single key/value extractor drives all rules. The checks target high-signal,
low-false-positive misconfigurations: debug mode left on, TLS verification
disabled, weak/deprecated TLS protocols, wildcard CORS, and authentication
turned off.

Secret *values* are intentionally NOT handled here - the dedicated secret scanner
already runs over every file, so duplicating it would only produce noise. No
file is executed; text is only read.
"""

from __future__ import annotations

import re

from models.enums import Confidence, FindingCategory, Severity
from scanners.finding import RuleFinding

SCANNER = "config-rules"

_MAX_EVIDENCE = 160

# key: value (YAML) | key = value (ini/TOML) | KEY=value (env) | "key": value (JSON)
_KV = re.compile(
    r"""^\s*["']?(?P<key>[A-Za-z0-9_.\-]+)["']?\s*[:=]\s*(?P<value>.*?)\s*,?\s*$"""
)

_TRUE = {"true", "1", "yes", "on", "enabled"}
_FALSE = {"false", "0", "no", "off", "disabled", "none", "null"}

# Keys whose *false* value disables TLS certificate verification.
_VERIFY_FALSE_KEYS = {
    "verify", "ssl_verify", "verify_ssl", "tls_verify", "sslverify",
    "rejectunauthorized", "validate_certs", "check_certificate", "checkcertificate",
    "ssl_verifypeer",
}
# Keys whose *true* value disables TLS certificate verification.
_VERIFY_TRUE_KEYS = {
    "insecure_skip_verify", "insecure", "skip_tls_verify", "tls_skip_verify",
    "allow_insecure", "disable_ssl_verification", "sslinsecure",
}
# Keys whose *false* value turns authentication off.
_AUTH_KEYS = {
    "auth", "authentication", "enable_auth", "auth_enabled", "require_auth",
    "authentication_enabled", "security_enabled", "enable_authentication",
    "auth_required",
}
# Keys that configure allowed CORS origins.
_CORS_KEYS = {
    "access-control-allow-origin", "cors_allow_origin", "cors_origins",
    "allowed_origins", "allow_origins", "allowedorigins", "alloworigins",
    "cors_allowed_origins",
}
# Keys that indicate a debug toggle.
_DEBUG_KEYS = {"debug", "debug_mode", "flask_debug", "app_debug", "django_debug"}

# Weak/deprecated TLS or SSL protocol versions (TLSv1.2 / 1.3 are excluded).
_WEAK_TLS = re.compile(r"\b(?:sslv2|sslv3|tlsv1(?![._]?[23]))", re.IGNORECASE)

_COMMENT_PREFIXES = ("#", "//", ";")


_META: dict[str, tuple[FindingCategory, Severity, Confidence, str, str, str]] = {
    "CFG001": (
        FindingCategory.SECURITY,
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "Debug mode enabled",
        "Debug mode exposes stack traces, internal paths and interactive "
        "debuggers, leaking sensitive detail and widening the attack surface if "
        "shipped to production.",
        "Disable debug mode in production configuration (set it to false).",
    ),
    "CFG002": (
        FindingCategory.SECURITY,
        Severity.HIGH,
        Confidence.HIGH,
        "TLS certificate verification disabled",
        "Disabling certificate verification allows an attacker to intercept the "
        "connection (man-in-the-middle) while it still appears encrypted.",
        "Enable certificate verification and fix the underlying trust chain "
        "instead of bypassing it.",
    ),
    "CFG003": (
        FindingCategory.SECURITY,
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "Weak or deprecated TLS/SSL protocol",
        "SSLv2, SSLv3 and TLSv1.0/1.1 have known cryptographic weaknesses and are "
        "deprecated.",
        "Require TLSv1.2 or TLSv1.3 and remove the legacy protocol versions.",
    ),
    "CFG004": (
        FindingCategory.SECURITY,
        Severity.MEDIUM,
        Confidence.HIGH,
        "Permissive CORS (wildcard origin)",
        "A wildcard CORS origin ('*') lets any website make cross-origin "
        "requests, which combined with credentials can expose user data.",
        "Restrict allowed origins to the specific trusted domains that need "
        "access.",
    ),
    "CFG005": (
        FindingCategory.SECURITY,
        Severity.HIGH,
        Confidence.HIGH,
        "Authentication disabled",
        "Authentication is explicitly turned off, leaving the service or "
        "component open to anonymous access.",
        "Enable authentication and require credentials for access.",
    ),
}


def _truncate(text: str) -> str:
    text = text.strip()
    return text if len(text) <= _MAX_EVIDENCE else text[: _MAX_EVIDENCE - 1] + "…"


def _make(rule_id: str, file_path: str, line: int, evidence: str) -> RuleFinding:
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
        evidence=_truncate(evidence),
    )


def _first_token(value: str) -> str:
    """Leading token of a value, unquoted and lowercased (ignores inline notes)."""
    if not value:
        return ""
    token = value.split()[0]
    return token.strip("'\"").strip(",").lower()


def analyze(text: str, file_path: str) -> list[RuleFinding]:
    """Analyse configuration text and return findings (pure, IO-free)."""
    findings: list[RuleFinding] = []

    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(_COMMENT_PREFIXES):
            continue

        match = _KV.match(line)
        if not match:
            continue
        key = match.group("key").strip().lower()
        value = match.group("value").strip()
        token = _first_token(value)
        is_true = token in _TRUE
        is_false = token in _FALSE

        if (key in _DEBUG_KEYS or key.endswith(".debug")) and is_true:
            findings.append(_make("CFG001", file_path, index, line))

        if (
            (key in _VERIFY_FALSE_KEYS and is_false)
            or (key in _VERIFY_TRUE_KEYS and is_true)
            or (key == "node_tls_reject_unauthorized" and token == "0")
        ):
            findings.append(_make("CFG002", file_path, index, line))

        if _WEAK_TLS.search(value):
            findings.append(_make("CFG003", file_path, index, line))

        if (key in _CORS_KEYS or "access-control-allow-origin" in key) and "*" in value:
            findings.append(_make("CFG004", file_path, index, line))

        if key in _AUTH_KEYS and is_false:
            findings.append(_make("CFG005", file_path, index, line))

    return findings
