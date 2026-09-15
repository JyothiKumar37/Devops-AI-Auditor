"""Heuristics that recognise configuration values which are not real secrets.

Keys such as ``ACCESS_TOKEN_TTL`` or ``REFRESH_TOKEN_TTL_DAYS`` match the
secret-key name patterns used by the generic credential detector (SEC010) and
the Kubernetes env-credential rule (K8S061), but their values are durations,
counts, booleans or symbolic constants - never live secrets. Skipping these
value shapes removes a common class of credential false positives without
masking genuine hardcoded secrets, which are high-entropy, mixed-case strings
rather than plain numbers or SCREAMING_SNAKE identifiers.
"""

from __future__ import annotations

import re

# A plain integer or decimal (e.g. "3600", "1.5").
_NUMBER_RE = re.compile(r"^\d+(?:\.\d+)?$")
# A duration literal (e.g. "3600s", "30m", "7d", "15 min", "24hours").
_DURATION_RE = re.compile(
    r"^\d+(?:\.\d+)?\s*"
    r"(?:ms|s|m|h|d|w|y|sec|secs|min|mins|hr|hrs|hour|hours|day|days|week|weeks)$",
    re.IGNORECASE,
)
# A symbolic constant / enum / error code (e.g. "AUTH_INVALID_TOKEN"). Requires
# at least one underscore-separated segment so opaque secrets (which have no
# such structure) are never matched.
_SCREAMING_SNAKE_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")

_BOOL_LIKE = frozenset(
    {"true", "false", "yes", "no", "on", "off", "none", "null", "nil", "n/a", "undefined"}
)

# Key suffixes that denote a duration, count or interval rather than a secret.
_NON_SECRET_KEY_SUFFIXES = (
    "_ttl", "_ttl_days", "_ttl_seconds", "_ttl_ms", "_timeout", "_timeout_ms",
    "_expiry", "_expires", "_expires_in", "_expiration", "_max_age", "_maxage",
    "_duration", "_interval", "_seconds", "_minutes", "_hours", "_days", "_ms",
    "_lifetime", "_leeway",
)


def is_non_secret_value(value: str) -> bool:
    """True if the value is a duration, number, boolean or symbolic constant."""
    stripped = value.strip().strip("\"'")
    if not stripped:
        return True
    if _NUMBER_RE.match(stripped) or _DURATION_RE.match(stripped):
        return True
    if stripped.lower() in _BOOL_LIKE:
        return True
    return bool(_SCREAMING_SNAKE_RE.match(stripped))


def is_duration_or_config_key(key: str) -> bool:
    """True if the key name denotes a TTL/timeout/duration/count, not a secret."""
    return key.lower().endswith(_NON_SECRET_KEY_SUFFIXES)
