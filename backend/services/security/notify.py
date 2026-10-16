"""Redaction-safe incident notifications (best-effort dispatch).

Builds provider-agnostic :class:`Notification` payloads from an incident and
dispatches them through the existing :class:`NotificationService`. Payloads carry
only non-sensitive summary fields (title, severity, resource ids, a link) - never
credentials, tokens, secret values, or raw event payloads. Dispatch is best-
effort: any delivery failure is swallowed so notification problems never affect
incident processing.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.logging import get_logger
from models.incident import Incident
from services.notifications import Notification

logger = get_logger(__name__)

# Human-readable titles per event type.
_TITLES = {
    "incident_created": "New security incident",
    "incident_critical": "CRITICAL security incident",
    "incident_unassigned": "Unassigned high-priority incident",
    "incident_severity_changed": "Incident severity changed",
    "containment_approval_requested": "Containment approval requested",
    "containment_failed": "Containment execution failed",
    "verification_failed": "Containment verification failed",
    "incident_resolved": "Incident resolved",
}


def _resource_hint(incident: Incident, resource_ids: list[str]) -> str:
    shown = ", ".join(resource_ids[:5])
    extra = f" (+{len(resource_ids) - 5} more)" if len(resource_ids) > 5 else ""
    return f"{shown}{extra}" if shown else "(no specific resource)"


async def notify_incident(
    session: AsyncSession,
    settings: Settings,
    incident: Incident,
    event_type: str,
    *,
    resource_ids: list[str] | None = None,
    extra: str = "",
) -> None:
    """Dispatch a redaction-safe incident notification (best-effort, never raises)."""
    # Imported lazily to avoid a service import cycle.
    from services.notification_service import NotificationService

    link = ""
    if settings.public_base_url:
        link = f"{settings.public_base_url.rstrip('/')}/incidents/{incident.id}"

    body = (
        f"Incident '{incident.title}' is {incident.severity} "
        f"(priority {incident.priority}, status {incident.status}). "
        f"Affected: {_resource_hint(incident, resource_ids or [])}."
    )
    if extra:
        body += f" {extra}"

    notification = Notification(
        event=event_type,
        title=_TITLES.get(event_type, "Security incident update"),
        body=body,
        severity=incident.severity,
        link=link or None,
        fields={
            "incident_id": str(incident.id),
            "severity": incident.severity,
            "priority": str(incident.priority),
            "status": incident.status,
            "account": incident.account_ref,
        },
    )
    try:
        await NotificationService(session, settings).dispatch(event_type, notification)
    except Exception as exc:  # noqa: BLE001 - notifications never break processing
        logger.warning("incident_notify_failed", notify_event=event_type, error=str(exc))
