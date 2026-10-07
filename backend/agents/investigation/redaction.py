"""Secret redaction applied at the tool boundary.

Repository file content, finding evidence, and other free text may contain live
secrets (API keys, tokens, private keys, passwords, connection strings). Before
ANY such text is handed to a tool result that the LLM will see, it is passed
through :func:`redact_secrets`, which replaces the sensitive portion with
``[REDACTED]`` while preserving enough structure to stay useful for analysis
(e.g. ``AWS_ACCESS_KEY_ID=[REDACTED]``).

This is defence-in-depth and intentionally conservative: it is better to redact
a borderline value than to leak a real credential to a third-party model. The
deterministic scanners still see the raw content; only the AI-facing projection
is redacted.
"""

from __future__ import annotations

import re

_PLACEHOLDER = "[REDACTED]"

# High-signal token shapes matched anywhere in the text.
_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"AKIA[0-9A-Z]{16}"),                      # AWS access key id
    re.compile(r"ASIA[0-9A-Z]{16}"),                      # AWS temporary key id
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),                  # GitHub PAT
    re.compile(r"gho_[A-Za-z0-9]{20,}"),                  # GitHub OAuth token
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),          # GitHub fine-grained PAT
    re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),             # GitLab PAT
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),         # Slack token
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                   # OpenAI-style secret key
    re.compile(r"AIza[0-9A-Za-z\-_]{30,}"),               # Google API key
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWT
)

# PEM private key blocks (multiline).
_PEM_RE = re.compile(
    r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----",
    re.DOTALL,
)

# key = value / key: value where the key name signals a secret. The value (quoted
# or bare) is redacted; the key is preserved so context remains readable.
_SECRET_KEY_HINT = (
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"secret[_-]?key|private[_-]?key|client[_-]?secret|auth|credential|"
    r"connection[_-]?string|conn[_-]?str|dsn|bearer)"
)
_ASSIGNMENT_RE = re.compile(
    rf"(?P<key>\b{_SECRET_KEY_HINT})(?P<sep>\s*[:=]\s*)(?P<quote>[\"']?)(?P<val>[^\s\"'#]+)(?P=quote)",
    re.IGNORECASE,
)

# Credentials embedded in a URL: scheme://user:password@host
_URL_CRED_RE = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:)(?P<pw>[^\s@/]+)(?P<at>@)")


def redact_secrets(text: str | None) -> str:
    """Return ``text`` with recognizable secrets replaced by ``[REDACTED]``.

    Safe on None/empty input (returns ""). Order matters: multiline PEM blocks
    first, then assignment-style secrets, URL credentials, and finally bare
    high-entropy token shapes.
    """
    if not text:
        return ""
    redacted = _PEM_RE.sub(_PLACEHOLDER, text)
    redacted = _ASSIGNMENT_RE.sub(
        lambda m: f"{m.group('key')}{m.group('sep')}{_PLACEHOLDER}", redacted
    )
    redacted = _URL_CRED_RE.sub(
        lambda m: f"{m.group('scheme')}{_PLACEHOLDER}{m.group('at')}", redacted
    )
    for pattern in _VALUE_PATTERNS:
        redacted = pattern.sub(_PLACEHOLDER, redacted)
    return redacted


def contains_secret(text: str | None) -> bool:
    """True if ``text`` appears to contain a redactable secret."""
    return bool(text) and redact_secrets(text) != text
