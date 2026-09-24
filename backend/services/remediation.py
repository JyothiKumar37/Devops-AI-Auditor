"""Deterministic remediation fixers.

Each fixer applies a single, unambiguous, non-inventing transformation to a
file's text (a boolean flip, a keyword swap, adding a well-defined safety flag,
or switching to a non-root user). Where a fix would require inventing a value
that cannot be derived safely - a specific image version, a resource limit, a
CIDR range - no fixer exists and the caller reports "Manual remediation
required." Nothing here guesses.

Fixers return the full patched content, or None when they cannot produce a
change. The diff helpers turn a before/after pair into a reviewable diff.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Callable
from dataclasses import dataclass

MANUAL_REQUIRED = "Manual remediation required."


@dataclass(frozen=True, slots=True)
class FixOutcome:
    new_content: str
    summary: str
    rationale: str


# A fixer takes (content, line, evidence) and returns patched content or None.
Fixer = Callable[[str, int | None, str | None], str | None]


def _sub_once(pattern: str, repl: str, content: str, flags: int = 0) -> str | None:
    new, count = re.subn(pattern, repl, content, count=1, flags=flags)
    return new if count else None


def _sub_line(pattern: str, repl: str, flags: int = 0) -> Callable[[str], str | None]:
    """Build a single-line transform that applies one regex substitution."""

    def transform(s: str) -> str | None:
        new, count = re.subn(pattern, repl, s, count=1, flags=flags)
        return new if count and new != s else None

    return transform


# Boolean-ish value tokens used by config/YAML flips.
_TRUTHY_TOKENS = frozenset({"true", "1", "yes", "on", "enabled"})
_FALSY_BOOL_TOKENS = frozenset({"false", "0", "no", "off", "disabled"})
# key: value | key = value | "key": value, capturing the value token to flip.
_KV_VALUE = re.compile(
    r'^(?P<pre>\s*["\']?[\w.\-]+["\']?\s*[:=]\s*["\']?)(?P<val>[A-Za-z0-9]+)(?P<post>.*)$'
)


def _flip_value(from_tokens: frozenset[str], target: str) -> Callable[[str], str | None]:
    """Build a transform that flips a boolean-ish value token to `target`.

    Only rewrites when the current value is one of `from_tokens`, so it never
    guesses on an unexpected value (e.g. 'none' is left for manual handling).
    """

    def transform(s: str) -> str | None:
        match = _KV_VALUE.match(s)
        if not match or match.group("val").lower() not in from_tokens:
            return None
        return match.group("pre") + target + match.group("post")

    return transform


def _replace_line(
    content: str, line: int | None, transform: Callable[[str], str | None]
) -> str | None:
    if not line:
        return None
    lines = content.splitlines(keepends=True)
    if line < 1 or line > len(lines):
        return None
    raw = lines[line - 1]
    newline = "\n" if raw.endswith("\n") else ""
    stripped = raw.rstrip("\n")
    changed = transform(stripped)
    if changed is None or changed == stripped:
        return None
    lines[line - 1] = changed + newline
    return "".join(lines)


# --- individual fixers ------------------------------------------------------


def _privileged_false(content: str, _line: int | None, _ev: str | None) -> str | None:
    return _sub_once(r"(privileged)(\s*:\s*)true", r"\1\2false", content)


def _ape_false(content: str, _line: int | None, _ev: str | None) -> str | None:
    return _sub_once(r"(allowPrivilegeEscalation)(\s*:\s*)true", r"\1\2false", content)


def _tf_public_false(content: str, _line: int | None, _ev: str | None) -> str | None:
    return _sub_once(r"(publicly_accessible)(\s*=\s*)true", r"\1\2false", content)


def _tf_encrypt_true(content: str, _line: int | None, _ev: str | None) -> str | None:
    return _sub_once(r"(storage_encrypted)(\s*=\s*)false", r"\1\2true", content)


def _ebs_encrypt_true(content: str, _line: int | None, _ev: str | None) -> str | None:
    return _sub_once(r"(\bencrypted)(\s*=\s*)false", r"\1\2true", content)


def _user_nonroot(content: str, _line: int | None, _ev: str | None) -> str | None:
    return _sub_once(r"(?m)^(\s*)USER\s+(?:root|0)\s*$", r"\1USER 1000", content)


def _append_user(content: str, _line: int | None, _ev: str | None) -> str | None:
    if re.search(r"(?m)^\s*USER\s+\S", content):
        return None  # already has a USER
    suffix = "" if content.endswith("\n") else "\n"
    return f"{content}{suffix}USER 1000\n"


def _add_to_copy(content: str, line: int | None, _ev: str | None) -> str | None:
    def t(s: str) -> str | None:
        if not re.match(r"^\s*ADD\b", s):
            return None
        # COPY cannot fetch remote URLs; only local ADD is safely convertible.
        if re.search(r"https?://", s):
            return None
        return re.sub(r"^(\s*)ADD\b", r"\1COPY", s)

    return _replace_line(content, line, t)


def _pip_no_cache(content: str, line: int | None, _ev: str | None) -> str | None:
    def t(s: str) -> str | None:
        if "--no-cache-dir" in s:
            return None
        return re.sub(r"(\bpip3?\s+install)\b", r"\1 --no-cache-dir", s, count=1)

    return _replace_line(content, line, t)


def _apt_no_recommends(content: str, line: int | None, _ev: str | None) -> str | None:
    def t(s: str) -> str | None:
        if "--no-install-recommends" in s:
            return None
        return re.sub(r"(\bapt-get\s+install)\b", r"\1 --no-install-recommends", s, count=1)

    return _replace_line(content, line, t)


# --- shell fixers -----------------------------------------------------------


def _remove_insecure_download_flags(
    content: str, line: int | None, _ev: str | None
) -> str | None:
    def t(s: str) -> str | None:
        new = re.sub(r"\s(?:-k|--insecure)\b", "", s)
        new = re.sub(r"\s--no-check-certificate\b", "", new)
        return new if new != s else None

    return _replace_line(content, line, t)


# --- ansible fixers ---------------------------------------------------------


def _ansible_validate_certs_true(content: str, line: int | None, _ev: str | None) -> str | None:
    return _replace_line(
        content, line, _sub_line(r"(validate_certs\s*:\s*)(?:no|false)\b", r"\g<1>true", re.I)
    )


def _ansible_state_present(content: str, line: int | None, _ev: str | None) -> str | None:
    return _replace_line(
        content, line, _sub_line(r"(state\s*:\s*['\"]?)latest\b", r"\g<1>present", re.I)
    )


# --- generic config fixers --------------------------------------------------


def _config_debug_false(content: str, line: int | None, _ev: str | None) -> str | None:
    return _replace_line(content, line, _flip_value(_TRUTHY_TOKENS, "false"))


def _config_auth_true(content: str, line: int | None, _ev: str | None) -> str | None:
    return _replace_line(content, line, _flip_value(_FALSY_BOOL_TOKENS, "true"))


# Keys whose secure value is truthy / falsy respectively (mirrors config rules).
_TLS_SECURE_TRUE_KEYS = frozenset(
    {
        "verify", "ssl_verify", "verify_ssl", "tls_verify", "sslverify",
        "rejectunauthorized", "validate_certs", "check_certificate",
        "checkcertificate", "ssl_verifypeer",
    }
)
_TLS_SECURE_FALSE_KEYS = frozenset(
    {
        "insecure_skip_verify", "insecure", "skip_tls_verify", "tls_skip_verify",
        "allow_insecure", "disable_ssl_verification", "sslinsecure",
    }
)


def _config_tls_verify(content: str, line: int | None, _ev: str | None) -> str | None:
    def t(s: str) -> str | None:
        key_match = re.match(r'^\s*["\']?(?P<key>[\w.\-]+)["\']?\s*[:=]', s)
        if not key_match:
            return None
        key = key_match.group("key").lower()
        if key in _TLS_SECURE_TRUE_KEYS:
            return _flip_value(_FALSY_BOOL_TOKENS, "true")(s)
        if key in _TLS_SECURE_FALSE_KEYS:
            return _flip_value(_TRUTHY_TOKENS, "false")(s)
        if key == "node_tls_reject_unauthorized":
            return _sub_line(r"([:=]\s*)0\b", r"\g<1>1")(s)
        return None

    return _replace_line(content, line, t)


# --- helm fixers ------------------------------------------------------------


def _helm_apiversion_v2(content: str, _line: int | None, _ev: str | None) -> str | None:
    return _sub_once(r"(?m)^(apiVersion\s*:\s*)v1\s*$", r"\g<1>v2", content)


def _helm_host_ns_false(content: str, line: int | None, _ev: str | None) -> str | None:
    return _replace_line(
        content,
        line,
        _sub_line(r"((?:hostNetwork|hostPID|hostIPC)\s*:\s*)true\b", r"\g<1>false"),
    )


def _helm_run_as_nonroot(content: str, line: int | None, _ev: str | None) -> str | None:
    def t(s: str) -> str | None:
        new = re.sub(r"(runAsNonRoot\s*:\s*)false\b", r"\g<1>true", s, count=1)
        new = re.sub(r"(runAsUser\s*:\s*)0\b", r"\g<1>1000", new, count=1)
        return new if new != s else None

    return _replace_line(content, line, t)


@dataclass(frozen=True, slots=True)
class _Spec:
    fixer: Fixer
    summary: str
    rationale: str


# rule_id -> fixer specification. Rules absent here have no safe automatic fix.
FIXERS: dict[str, _Spec] = {
    # Docker
    "DCK003": _Spec(
        _user_nonroot, "Run as a non-root user",
        "Replace 'USER root' with a non-root UID (1000).",
    ),
    "DCK004": _Spec(
        _append_user, "Add a non-root USER",
        "Append 'USER 1000' so the container does not run as root.",
    ),
    "DCK008": _Spec(
        _pip_no_cache, "Add --no-cache-dir",
        "Avoid caching pip wheels in the image layer.",
    ),
    "DCK011": _Spec(
        _add_to_copy, "Use COPY instead of ADD",
        "COPY is safer than ADD for local files.",
    ),
    "DCK015": _Spec(
        _apt_no_recommends, "Add --no-install-recommends",
        "Avoid pulling unnecessary packages.",
    ),
    # Docker Compose
    "DCMP001": _Spec(
        _privileged_false, "Disable privileged mode", "Set privileged: false.",
    ),
    # Kubernetes
    "K8S001": _Spec(
        _privileged_false, "Disable privileged container",
        "Set securityContext.privileged: false.",
    ),
    "K8S006": _Spec(
        _ape_false, "Disable privilege escalation",
        "Set allowPrivilegeEscalation: false.",
    ),
    # Terraform
    "TF004": _Spec(
        _tf_public_false, "Make the database private",
        "Set publicly_accessible = false.",
    ),
    "TF006": _Spec(
        _tf_encrypt_true, "Enable encryption at rest",
        "Set storage_encrypted = true.",
    ),
    # Shell
    "SH007": _Spec(
        _remove_insecure_download_flags, "Remove the TLS-bypass flag",
        "Drop -k/--insecure/--no-check-certificate so the download verifies TLS.",
    ),
    # Ansible
    "ANS002": _Spec(
        _ansible_validate_certs_true, "Enable certificate verification",
        "Set validate_certs: true.",
    ),
    "ANS006": _Spec(
        _ansible_state_present, "Pin package state to 'present'",
        "Replace 'state: latest' with 'state: present' for reproducible runs.",
    ),
    # Generic configuration
    "CFG001": _Spec(
        _config_debug_false, "Disable debug mode", "Set the debug flag to false.",
    ),
    "CFG002": _Spec(
        _config_tls_verify, "Re-enable TLS verification",
        "Set the verification flag back to its secure value.",
    ),
    "CFG005": _Spec(
        _config_auth_true, "Enable authentication",
        "Turn authentication back on (set it to true).",
    ),
    # Helm
    "HELM001": _Spec(
        _helm_apiversion_v2, "Upgrade chart to apiVersion v2",
        "Set 'apiVersion: v2' for Helm 3.",
    ),
    "HELM011": _Spec(
        _privileged_false, "Disable privileged container",
        "Set securityContext.privileged: false.",
    ),
    "HELM012": _Spec(
        _helm_host_ns_false, "Disable host namespace sharing",
        "Set hostNetwork/hostPID/hostIPC to false.",
    ),
    "HELM013": _Spec(
        _helm_run_as_nonroot, "Run as a non-root user",
        "Set runAsNonRoot: true / a non-root runAsUser.",
    ),
    "HELM014": _Spec(
        _ape_false, "Disable privilege escalation",
        "Set allowPrivilegeEscalation: false.",
    ),
}
# aws_ebs_volume uses a bare `encrypted` attribute; handle that TF006 variant too.
_EBS_FALLBACK = _Spec(_ebs_encrypt_true, "Enable encryption", "Set encrypted = true.")


def propose_fix(
    content: str, rule_id: str, line: int | None, evidence: str | None
) -> FixOutcome | None:
    """Return a safe patched version for a finding, or None if none exists."""
    spec = FIXERS.get(rule_id)
    if spec is None:
        return None
    new_content = spec.fixer(content, line, evidence)
    if new_content is None and rule_id == "TF006":
        # Try the aws_ebs_volume 'encrypted' variant.
        new_content = _EBS_FALLBACK.fixer(content, line, evidence)
        if new_content is not None:
            spec = _EBS_FALLBACK
    if new_content is None or new_content == content:
        return None
    return FixOutcome(new_content=new_content, summary=spec.summary, rationale=spec.rationale)


def build_diff(path: str, before: str, after: str) -> str:
    """Return a unified diff between before and after."""
    diff = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        n=2,
    )
    return "".join(diff)


def changed_lines(before: str, after: str) -> tuple[str, str]:
    """Return (removed, added) line text for the first changed hunk."""
    removed: list[str] = []
    added: list[str] = []
    matcher = difflib.SequenceMatcher(a=before.splitlines(), b=after.splitlines())
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in {"replace", "delete"}:
            removed.extend(before.splitlines()[i1:i2])
        if tag in {"replace", "insert"}:
            added.extend(after.splitlines()[j1:j2])
    return "\n".join(removed), "\n".join(added)
