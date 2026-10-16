"""Adapters for webhook-delivered sources: CI/CD, Falco, Alertmanager.

All inbound payloads are UNTRUSTED. Parsing is defensive (missing/renamed fields
never raise), the resulting events are ``verified=False``, and every string is
secret-redacted + bounded by :meth:`NormalizedEvent.redacted` at ingest.
"""

from __future__ import annotations

import uuid
from typing import Any

from models.enums import SecurityEventCategory, SecurityEventSourceType, Severity
from services.security.normalize import NormalizedEvent

_FALCO_PRIORITY: dict[str, str] = {
    "emergency": Severity.CRITICAL.value,
    "alert": Severity.CRITICAL.value,
    "critical": Severity.CRITICAL.value,
    "error": Severity.HIGH.value,
    "warning": Severity.MEDIUM.value,
    "notice": Severity.LOW.value,
    "informational": Severity.INFO.value,
    "info": Severity.INFO.value,
    "debug": Severity.INFO.value,
}

_LABEL_SEVERITY: dict[str, str] = {
    "critical": Severity.CRITICAL.value,
    "high": Severity.HIGH.value,
    "warning": Severity.MEDIUM.value,
    "medium": Severity.MEDIUM.value,
    "low": Severity.LOW.value,
    "info": Severity.INFO.value,
    "none": Severity.INFO.value,
}


def _str(value: Any, default: str = "") -> str:
    return str(value) if value is not None else default


def events_from_cicd(
    payload: dict[str, Any], *, cloud_account_id: uuid.UUID | None = None
) -> list[NormalizedEvent]:
    """Normalize a CI/CD pipeline security-failure webhook.

    Expected shape (lenient)::

        {"pipeline": str, "repository": str, "commit": str,
         "failures": [{"id","rule","severity","title","description","resource"}]}
    """
    repo = _str(payload.get("repository"))
    pipeline = _str(payload.get("pipeline"))
    commit = _str(payload.get("commit"))
    failures = payload.get("failures")
    if not isinstance(failures, list):
        failures = [payload]  # allow a single-failure payload
    events: list[NormalizedEvent] = []
    for item in failures:
        if not isinstance(item, dict):
            continue
        sev = _LABEL_SEVERITY.get(_str(item.get("severity")).lower(), Severity.MEDIUM.value)
        fid = _str(item.get("id")) or _str(item.get("rule")) or _str(item.get("title"))
        events.append(
            NormalizedEvent(
                source_type=SecurityEventSourceType.CICD.value,
                source_event_id=f"{pipeline}:{commit}:{fid}",
                category=SecurityEventCategory.PIPELINE.value,
                event_type=_str(item.get("rule"), "ci_security_failure"),
                severity=sev,
                confidence="medium",
                title=_str(item.get("title"), "CI/CD security failure"),
                description=_str(item.get("description")),
                account_ref=repo,
                resource_id=_str(item.get("resource")) or (f"repo:{repo}" if repo else ""),
                verified=False,
                evidence={"pipeline": pipeline, "commit": commit, "rule": item.get("rule", "")},
                provenance={"kind": "cicd", "repository": repo},
            )
        )
    return events


def event_from_falco(
    payload: dict[str, Any], *, cloud_account_id: uuid.UUID | None = None
) -> NormalizedEvent:
    """Normalize a Falco runtime-security alert."""
    fields = payload.get("output_fields", {}) or {}
    resource = (
        _str(fields.get("k8s.pod.name"))
        or _str(fields.get("container.name"))
        or _str(fields.get("container.id"))
        or _str(payload.get("hostname"))
    )
    rule = _str(payload.get("rule"), "Falco rule")
    return NormalizedEvent(
        source_type=SecurityEventSourceType.FALCO.value,
        source_event_id=f"falco:{rule}:{resource}:{_str(payload.get('time'))}",
        category=SecurityEventCategory.RUNTIME.value,
        event_type=rule,
        severity=_FALCO_PRIORITY.get(_str(payload.get("priority")).lower(), Severity.MEDIUM.value),
        confidence="medium",
        title=rule,
        description=_str(payload.get("output")),
        resource_id=resource,
        source_ip=_str(fields.get("fd.cip")),
        verified=False,
        evidence={
            "namespace": _str(fields.get("k8s.ns.name")),
            "image": _str(fields.get("container.image.repository")),
        },
        provenance={"kind": "falco", "rule": rule},
    )


def events_from_alertmanager(
    payload: dict[str, Any], *, cloud_account_id: uuid.UUID | None = None
) -> list[NormalizedEvent]:
    """Normalize a Prometheus Alertmanager webhook (only firing alerts)."""
    alerts = payload.get("alerts")
    if not isinstance(alerts, list):
        return []
    events: list[NormalizedEvent] = []
    for alert in alerts:
        if not isinstance(alert, dict) or alert.get("status") != "firing":
            continue
        labels = alert.get("labels", {}) or {}
        annotations = alert.get("annotations", {}) or {}
        name = _str(labels.get("alertname"), "alert")
        sev = _LABEL_SEVERITY.get(_str(labels.get("severity")).lower(), Severity.MEDIUM.value)
        source_event_id = _str(alert.get("fingerprint")) or f"{name}:{_str(labels.get('instance'))}"
        events.append(
            NormalizedEvent(
                source_type=SecurityEventSourceType.ALERTMANAGER.value,
                source_event_id=source_event_id,
                category=SecurityEventCategory.RUNTIME.value,
                event_type=name,
                severity=sev,
                confidence="medium",
                title=_str(annotations.get("summary"), name),
                description=_str(annotations.get("description")),
                resource_id=_str(labels.get("instance")) or _str(labels.get("job")),
                verified=False,
                evidence={k: _str(v) for k, v in list(labels.items())[:10]},
                provenance={"kind": "alertmanager", "alertname": name},
            )
        )
    return events
