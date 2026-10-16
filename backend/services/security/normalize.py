"""The source-agnostic normalized security event + helpers.

Every ingestion adapter produces a :class:`NormalizedEvent`. The event carries a
stable, content-based :meth:`fingerprint` so repeated delivery of the same
underlying signal deduplicates instead of creating duplicates. All free-text and
nested payloads are secret-redacted and size-bounded by :func:`redact_payload`
BEFORE anything is persisted - external event content is untrusted data.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from agents.investigation.redaction import redact_secrets
from models.enums import SecurityEventCategory, Severity

# Bound how much nested provenance we keep so a hostile payload cannot bloat the DB.
_MAX_STR = 2000
_MAX_ITEMS = 50
_MAX_DEPTH = 6


def redact_payload(value: Any, *, _depth: int = 0) -> Any:
    """Recursively secret-redact and size-bound an arbitrary JSON-ish value."""
    if _depth >= _MAX_DEPTH:
        return "[truncated]"
    if isinstance(value, str):
        return redact_secrets(value)[:_MAX_STR] if value else value
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= _MAX_ITEMS:
                break
            out[str(k)[:128]] = redact_payload(v, _depth=_depth + 1)
        return out
    if isinstance(value, list | tuple):
        return [redact_payload(v, _depth=_depth + 1) for v in list(value)[:_MAX_ITEMS]]
    if isinstance(value, int | float | bool) or value is None:
        return value
    return redact_secrets(str(value))[:_MAX_STR]


def numeric_severity_to_level(score: float) -> str:
    """Map a GuardDuty/ASFF-style numeric severity (0-10) to our Severity level."""
    if score >= 8:
        return Severity.CRITICAL.value
    if score >= 7:
        return Severity.HIGH.value
    if score >= 4:
        return Severity.MEDIUM.value
    if score >= 1:
        return Severity.LOW.value
    return Severity.INFO.value


@dataclass(slots=True)
class NormalizedEvent:
    """A single normalized security signal, ready to ingest."""

    source_type: str
    source_event_id: str
    category: str
    event_type: str
    severity: str
    title: str
    description: str = ""
    confidence: str = "medium"
    cloud_account_id: uuid.UUID | None = None
    account_ref: str = ""
    region: str = ""
    resource_id: str = ""
    resource_arn: str = ""
    principal: str = ""
    source_ip: str = ""
    # True ONLY when produced by our own deterministic engines (repo/cloud scans).
    verified: bool = False
    related_finding_ids: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)
    observed_at: datetime | None = None

    def fingerprint(self) -> str:
        """Stable dedup fingerprint over the signal's identity (not its timestamp).

        Includes the source, the source's own event id, the subject resource and
        the event type. Two deliveries of the same GuardDuty finding, or the same
        deterministic finding re-emitted on a later scan, collapse to one row.
        """
        basis = "|".join(
            [
                self.source_type,
                self.source_event_id or "",
                self.resource_id or "",
                self.event_type or "",
            ]
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:64]

    def normalized_category(self) -> str:
        """Coerce the category to a known value (defaults to OTHER)."""
        try:
            return SecurityEventCategory(self.category).value
        except ValueError:
            return SecurityEventCategory.OTHER.value

    def redacted(self) -> NormalizedEvent:
        """Return a copy with all free text + payloads secret-redacted + bounded."""
        return NormalizedEvent(
            source_type=self.source_type,
            source_event_id=self.source_event_id[:512],
            category=self.normalized_category(),
            event_type=self.event_type[:128],
            severity=self.severity,
            title=redact_secrets(self.title)[:512] or "Security event",
            description=redact_secrets(self.description)[:_MAX_STR],
            confidence=self.confidence,
            cloud_account_id=self.cloud_account_id,
            account_ref=self.account_ref[:64],
            region=self.region[:32],
            resource_id=redact_secrets(self.resource_id)[:512],
            resource_arn=self.resource_arn[:1024],
            principal=redact_secrets(self.principal)[:512],
            source_ip=self.source_ip[:64],
            verified=self.verified,
            related_finding_ids=[str(f) for f in self.related_finding_ids][:_MAX_ITEMS],
            evidence=redact_payload(self.evidence),
            provenance=redact_payload(self.provenance),
            observed_at=self.observed_at,
        )
