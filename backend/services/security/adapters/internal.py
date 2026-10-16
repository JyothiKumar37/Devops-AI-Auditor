"""Adapters for INTERNAL, verified sources (our own deterministic engines).

Findings and cloud changes produced by the Phase 1-4 engines are the gold
standard: they are reproducible and independently verifiable, so the resulting
events are marked ``verified=True``. These adapters are the bridge that lets a
deterministic finding participate in incident correlation without duplicating it.
"""

from __future__ import annotations

import uuid
from typing import Any

from models.cloud import CloudAccount, CloudChange, CloudFinding
from models.enums import SecurityEventCategory, SecurityEventSourceType, Severity
from models.finding import Finding
from services.security.normalize import NormalizedEvent

# Map a finding category onto a coarse security-event category.
_CATEGORY_MAP: dict[str, str] = {
    "security": SecurityEventCategory.MISCONFIGURATION.value,
    "secrets": SecurityEventCategory.EXPOSURE.value,
    "supply_chain": SecurityEventCategory.VULNERABILITY.value,
    "configuration": SecurityEventCategory.MISCONFIGURATION.value,
    "reliability": SecurityEventCategory.OTHER.value,
    "efficiency": SecurityEventCategory.OTHER.value,
    "best_practice": SecurityEventCategory.OTHER.value,
    "network": SecurityEventCategory.EXPOSURE.value,
    "iam": SecurityEventCategory.IDENTITY.value,
    "compliance": SecurityEventCategory.COMPLIANCE.value,
}


def _v(x: Any) -> str:
    return x.value if hasattr(x, "value") else str(x)


def _category(raw: str) -> str:
    return _CATEGORY_MAP.get(raw.lower(), SecurityEventCategory.MISCONFIGURATION.value)


def event_from_repo_finding(
    finding: Finding, path: str | None, repository_name: str
) -> NormalizedEvent:
    """Normalize a repository scan finding into a verified security event."""
    resource = f"repo:{repository_name}:{path}" if path else f"repo:{repository_name}"
    return NormalizedEvent(
        source_type=SecurityEventSourceType.REPO_SCAN.value,
        source_event_id=str(finding.id),
        category=_category(_v(finding.category)),
        event_type=finding.rule_id,
        severity=_v(finding.severity),
        confidence=_v(finding.confidence),
        title=finding.title,
        description=finding.description or "",
        resource_id=resource,
        account_ref=repository_name,
        verified=True,
        related_finding_ids=[str(finding.id)],
        evidence={
            "rule_id": finding.rule_id,
            "scanner": finding.scanner,
            "file": path or "",
            "line": finding.line_number,
            "recommendation": finding.recommendation or "",
            # Secret-redacted + bounded by NormalizedEvent.redacted() at ingest.
            "detail": finding.evidence or "",
        },
        provenance={"kind": "repo_finding", "scan_id": str(finding.scan_id)},
    )


def event_from_cloud_finding(finding: CloudFinding, account: CloudAccount) -> NormalizedEvent:
    """Normalize a deterministic cloud finding into a verified security event."""
    return NormalizedEvent(
        source_type=SecurityEventSourceType.CLOUD_SCAN.value,
        source_event_id=str(finding.id),
        category=_category(finding.category),
        event_type=finding.rule_id,
        severity=finding.severity,
        confidence=finding.confidence,
        title=finding.title,
        description=finding.description or "",
        cloud_account_id=account.id,
        account_ref=account.account_id,
        region=finding.region,
        resource_id=finding.resource_id,
        verified=True,
        related_finding_ids=[str(finding.id)],
        evidence={
            "rule_id": finding.rule_id,
            "service": finding.service,
            "recommendation": finding.recommendation or "",
            "compliance": list(finding.compliance or []),
        },
        provenance={"kind": "cloud_finding", "account_id": str(account.id)},
    )


def event_from_cloud_change(change: CloudChange, account: CloudAccount) -> NormalizedEvent:
    """Normalize a detected cloud change into a verified security event.

    Risk-significant changes (new public exposure, world-open admin/db ports, RDS
    public flips) are HIGH; ordinary changes are informational drift signals.
    """
    significant = bool(change.risk_significant)
    category = (
        SecurityEventCategory.EXPOSURE.value if significant else SecurityEventCategory.DRIFT.value
    )
    severity = Severity.HIGH.value if significant else Severity.LOW.value
    return NormalizedEvent(
        source_type=SecurityEventSourceType.CLOUD_CHANGE.value,
        source_event_id=str(change.id),
        category=category,
        event_type=change.change_type,
        severity=severity,
        confidence="high",
        title=f"Cloud resource {change.change_type}: {change.resource_id}",
        description="",
        cloud_account_id=account.id,
        account_ref=account.account_id,
        resource_id=change.resource_id,
        verified=True,
        evidence={"service": change.service, "detail": dict(change.detail or {})},
        provenance={"kind": "cloud_change", "change_id": str(change.id)},
    )


def resource_uuid_safe(value: str) -> uuid.UUID | None:
    """Best-effort parse of a UUID string (used when linking optional ids)."""
    try:
        return uuid.UUID(value)
    except (ValueError, TypeError):
        return None
