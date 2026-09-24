"""Deterministic Helm rule engine.

Helm templates embed Go templating (``{{ ... }}``) and therefore are not valid
YAML, so a full parse is not viable. This engine is line/regex based, matching
literal (non-templated) declarations that carry real risk:

- ``Chart.yaml`` metadata: deprecated Helm 2 ``apiVersion: v1`` and a missing
  chart ``version``.
- ``values.yaml`` defaults and rendered ``templates/`` alike: privileged
  containers, host namespaces, running as root, privilege escalation, dangerous
  Linux capabilities and unpinned (``:latest``) images.

Templated values (``privileged: {{ .Values.x }}``) are deliberately not flagged -
their value is unknown at scan time. No template is ever executed; text is only
read.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from models.enums import Confidence, FindingCategory, Severity
from scanners.finding import RuleFinding

SCANNER = "helm-rules"

_MAX_EVIDENCE = 160

_CHART_FILENAMES = {"chart.yaml", "chart.yml"}

# Chart.yaml metadata patterns (matched against the stripped line).
_CHART_APIVERSION = re.compile(r"^apiVersion\s*:\s*(?P<v>\S+)", re.IGNORECASE)
_VERSION_KEY = re.compile(r"^version\s*:\s*\S", re.IGNORECASE)

# Shared security / best-practice patterns for values.yaml and templates.
_IMG_LATEST = re.compile(
    r"\btag\s*:\s*['\"]?latest\b|\bimage\s*:\s*['\"]?[^\s'\"{}]+:latest\b", re.IGNORECASE
)
_PRIVILEGED = re.compile(r"\bprivileged\s*:\s*true\b", re.IGNORECASE)
_HOST_NS = re.compile(r"\b(?:hostNetwork|hostPID|hostIPC)\s*:\s*true\b")
_RUN_AS_ROOT = re.compile(r"\brunAsNonRoot\s*:\s*false\b|\brunAsUser\s*:\s*0\b")
_PRIV_ESC = re.compile(r"\ballowPrivilegeEscalation\s*:\s*true\b")
# Dangerous capabilities that are almost always *added*, never dropped - keying
# on the "- CAP" list form avoids flagging "drop: [ALL]" (a good practice).
_DANGEROUS_CAP = re.compile(
    r"-\s*['\"]?(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|NET_RAW|SYS_MODULE)\b"
)


_META: dict[str, tuple[FindingCategory, Severity, Confidence, str, str, str]] = {
    "HELM001": (
        FindingCategory.BEST_PRACTICE,
        Severity.LOW,
        Confidence.HIGH,
        "Deprecated Helm 2 chart apiVersion",
        "'apiVersion: v1' marks a Helm 2 chart; Helm 3 charts use apiVersion v2, "
        "and Helm 2 is end-of-life.",
        "Migrate the chart to 'apiVersion: v2' for Helm 3.",
    ),
    "HELM002": (
        FindingCategory.RELIABILITY,
        Severity.LOW,
        Confidence.HIGH,
        "Chart is missing a version",
        "Chart.yaml declares no 'version', so the chart cannot be reliably "
        "packaged, tracked or upgraded.",
        "Add a semantic 'version' field to Chart.yaml.",
    ),
    "HELM010": (
        FindingCategory.BEST_PRACTICE,
        Severity.MEDIUM,
        Confidence.HIGH,
        "Unpinned image tag ('latest')",
        "Using the 'latest' tag makes deployments non-reproducible: the image "
        "pulled depends on when the release is installed.",
        "Pin an explicit, immutable image tag (ideally a digest).",
    ),
    "HELM011": (
        FindingCategory.SECURITY,
        Severity.HIGH,
        Confidence.HIGH,
        "Privileged container",
        "A privileged container has near-unrestricted access to the host, so a "
        "compromise effectively compromises the node.",
        "Remove 'privileged: true' and grant only the specific capabilities "
        "required.",
    ),
    "HELM012": (
        FindingCategory.SECURITY,
        Severity.HIGH,
        Confidence.HIGH,
        "Host namespace shared",
        "Sharing the host network, PID or IPC namespace breaks pod isolation and "
        "exposes host processes and interfaces to the container.",
        "Remove hostNetwork/hostPID/hostIPC unless there is a vetted requirement.",
    ),
    "HELM013": (
        FindingCategory.SECURITY,
        Severity.MEDIUM,
        Confidence.HIGH,
        "Container runs as root",
        "Running as root (runAsUser 0 or runAsNonRoot false) means a container "
        "breakout starts with root on the host.",
        "Set runAsNonRoot: true and run as a dedicated non-root UID.",
    ),
    "HELM014": (
        FindingCategory.SECURITY,
        Severity.MEDIUM,
        Confidence.HIGH,
        "Privilege escalation allowed",
        "allowPrivilegeEscalation: true lets a process gain more privileges than "
        "its parent (e.g. via setuid binaries).",
        "Set allowPrivilegeEscalation: false.",
    ),
    "HELM015": (
        FindingCategory.SECURITY,
        Severity.HIGH,
        Confidence.MEDIUM,
        "Dangerous Linux capability added",
        "Adding capabilities such as SYS_ADMIN or NET_ADMIN grants powerful, "
        "host-affecting privileges that are frequently abused in escapes.",
        "Drop all capabilities and add back only the minimal set genuinely "
        "required.",
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


def _analyze_chart(text: str, file_path: str) -> list[RuleFinding]:
    """Chart.yaml metadata rules."""
    findings: list[RuleFinding] = []
    saw_version = False

    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        api_match = _CHART_APIVERSION.match(line)
        if api_match and api_match.group("v").strip("'\"").lower() == "v1":
            findings.append(_make("HELM001", file_path, index, line))
        if _VERSION_KEY.match(line):
            saw_version = True

    if not saw_version:
        findings.append(_make("HELM002", file_path, 1, "Chart.yaml has no 'version' field"))
    return findings


def _analyze_manifest(text: str, file_path: str) -> list[RuleFinding]:
    """Security/best-practice rules for values.yaml and rendered templates."""
    findings: list[RuleFinding] = []
    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if _IMG_LATEST.search(line):
            findings.append(_make("HELM010", file_path, index, line))
        if _PRIVILEGED.search(line):
            findings.append(_make("HELM011", file_path, index, line))
        if _HOST_NS.search(line):
            findings.append(_make("HELM012", file_path, index, line))
        if _RUN_AS_ROOT.search(line):
            findings.append(_make("HELM013", file_path, index, line))
        if _PRIV_ESC.search(line):
            findings.append(_make("HELM014", file_path, index, line))
        if _DANGEROUS_CAP.search(line):
            findings.append(_make("HELM015", file_path, index, line))
    return findings


def analyze(text: str, file_path: str) -> list[RuleFinding]:
    """Analyse a Helm file (Chart.yaml / values.yaml / template) and return findings."""
    if PurePosixPath(file_path).name.lower() in _CHART_FILENAMES:
        return _analyze_chart(text, file_path)
    return _analyze_manifest(text, file_path)
