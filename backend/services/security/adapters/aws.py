"""Adapters for AWS-native security sources (externally reported, UNVERIFIED).

These normalize GuardDuty findings, Security Hub (ASFF) findings, CloudTrail
events and AWS Config changes into :class:`NormalizedEvent`. The resulting events
are ``verified=False`` - they are signals from AWS that may warrant investigation,
but they are not corroborated by our own deterministic engines until correlation
links them to a verified finding.

The ``poll_*`` helpers call the (read-only, assumed-role) AWS APIs. They are
defensive: any API/permission error is swallowed and surfaced via source health,
never raised into a request. In tests the normalizers are exercised directly with
recorded fixtures, so no live AWS account is required.
"""

from __future__ import annotations

import uuid
from typing import Any

from core.logging import get_logger
from models.enums import SecurityEventCategory, SecurityEventSourceType, Severity
from services.security.normalize import NormalizedEvent, numeric_severity_to_level

logger = get_logger(__name__)


def _first(seq: Any) -> dict[str, Any]:
    if isinstance(seq, list) and seq and isinstance(seq[0], dict):
        return seq[0]
    return {}


def _is_arn(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("arn:")


# CloudTrail event names that mutate state (elevated from informational to medium).
_SENSITIVE_CT_KEYWORDS = ("delete", "create", "put", "attach", "authorize", "disable")


def event_from_guardduty(
    finding: dict[str, Any], *, account_ref: str, cloud_account_id: uuid.UUID | None
) -> NormalizedEvent:
    """Normalize an Amazon GuardDuty finding."""
    resource = finding.get("Resource", {}) or {}
    service = finding.get("Service", {}) or {}
    action = service.get("Action", {}) or {}
    remote = (
        action.get("NetworkConnectionAction", {}).get("RemoteIpDetails", {})
        or action.get("AwsApiCallAction", {}).get("RemoteIpDetails", {})
        or {}
    )
    instance = resource.get("InstanceDetails", {}) or {}
    access_key = resource.get("AccessKeyDetails", {}) or {}
    resource_id = (
        instance.get("InstanceId")
        or access_key.get("UserName")
        or resource.get("ResourceType")
        or ""
    )
    return NormalizedEvent(
        source_type=SecurityEventSourceType.GUARDDUTY.value,
        source_event_id=str(finding.get("Id", "")),
        category=SecurityEventCategory.THREAT.value,
        event_type=str(finding.get("Type", "")),
        severity=numeric_severity_to_level(float(finding.get("Severity", 0) or 0)),
        confidence="medium",
        title=str(finding.get("Title", finding.get("Type", "GuardDuty finding"))),
        description=str(finding.get("Description", "")),
        cloud_account_id=cloud_account_id,
        account_ref=str(finding.get("AccountId", account_ref)),
        region=str(finding.get("Region", "")),
        resource_id=str(resource_id),
        principal=str(access_key.get("UserName", "")),
        source_ip=str(remote.get("IpAddressV4", "")),
        verified=False,
        evidence={
            "type": finding.get("Type", ""),
            "action_type": action.get("ActionType", ""),
            "count": service.get("Count", 0),
        },
        provenance={"kind": "guardduty", "finding": finding},
    )


def event_from_security_hub(
    finding: dict[str, Any], *, account_ref: str, cloud_account_id: uuid.UUID | None
) -> NormalizedEvent:
    """Normalize an AWS Security Hub (ASFF) finding."""
    severity_block = finding.get("Severity", {}) or {}
    label = str(severity_block.get("Label", "")).lower()
    if label in {"informational", "low", "medium", "high", "critical"}:
        severity = "info" if label == "informational" else label
    else:
        severity = numeric_severity_to_level(
            float(severity_block.get("Normalized", 0) or 0) / 10.0
        )
    resource = _first(finding.get("Resources", []))
    return NormalizedEvent(
        source_type=SecurityEventSourceType.SECURITY_HUB.value,
        source_event_id=str(finding.get("Id", "")),
        category=SecurityEventCategory.COMPLIANCE.value,
        event_type=str((finding.get("Types") or [""])[0]),
        severity=severity,
        confidence="medium",
        title=str(finding.get("Title", "Security Hub finding")),
        description=str(finding.get("Description", "")),
        cloud_account_id=cloud_account_id,
        account_ref=str(finding.get("AwsAccountId", account_ref)),
        region=str(resource.get("Region", finding.get("Region", ""))),
        resource_id=str(resource.get("Id", "")),
        resource_arn=str(resource.get("Id", "")) if _is_arn(resource.get("Id")) else "",
        verified=False,
        evidence={
            "product": finding.get("ProductName", ""),
            "compliance": (finding.get("Compliance", {}) or {}).get("Status", ""),
        },
        provenance={"kind": "security_hub", "finding": finding},
    )


def event_from_cloudtrail(
    event: dict[str, Any], *, account_ref: str, cloud_account_id: uuid.UUID | None
) -> NormalizedEvent:
    """Normalize a CloudTrail management event (identity/activity signal)."""
    resources = event.get("Resources", []) or []
    resource_id = ""
    if resources and isinstance(resources[0], dict):
        resource_id = str(resources[0].get("ResourceName", ""))
    sensitive = str(event.get("EventName", "")).lower()
    severity = (
        Severity.MEDIUM.value
        if any(k in sensitive for k in _SENSITIVE_CT_KEYWORDS)
        else Severity.LOW.value
    )
    return NormalizedEvent(
        source_type=SecurityEventSourceType.CLOUDTRAIL.value,
        source_event_id=str(event.get("EventId", "")),
        category=SecurityEventCategory.IDENTITY.value,
        event_type=str(event.get("EventName", "")),
        severity=severity,
        confidence="low",
        title=f"CloudTrail: {event.get('EventName', 'event')}",
        description=str(event.get("EventSource", "")),
        cloud_account_id=cloud_account_id,
        account_ref=account_ref,
        region=str(event.get("awsRegion", event.get("Region", ""))),
        resource_id=resource_id,
        principal=str(event.get("Username", "")),
        source_ip=str(event.get("SourceIPAddress", "")),
        verified=False,
        evidence={"event_source": event.get("EventSource", "")},
        provenance={"kind": "cloudtrail", "event_name": event.get("EventName", "")},
    )


def event_from_config(
    item: dict[str, Any], *, account_ref: str, cloud_account_id: uuid.UUID | None
) -> NormalizedEvent:
    """Normalize an AWS Config configuration/compliance change."""
    compliance = str(item.get("complianceType", "")).upper()
    severity = Severity.MEDIUM.value if compliance == "NON_COMPLIANT" else Severity.LOW.value
    return NormalizedEvent(
        source_type=SecurityEventSourceType.CONFIG.value,
        source_event_id=str(item.get("configurationItemId", item.get("resourceId", ""))),
        category=SecurityEventCategory.DRIFT.value,
        event_type=str(item.get("configurationItemStatus", "ConfigurationChange")),
        severity=severity,
        confidence="medium",
        title=f"Config change: {item.get('resourceType', 'resource')}",
        description=str(item.get("configurationItemStatus", "")),
        cloud_account_id=cloud_account_id,
        account_ref=str(item.get("awsAccountId", account_ref)),
        region=str(item.get("awsRegion", "")),
        resource_id=str(item.get("resourceId", "")),
        resource_arn=str(item.get("arn", "")),
        verified=False,
        evidence={"resource_type": item.get("resourceType", ""), "compliance": compliance},
        provenance={"kind": "aws_config", "resource_type": item.get("resourceType", "")},
    )


# ---- read-only polling wrappers (defensive; exercised via fixtures in tests) ---


def poll_guardduty(assumed: Any, region: str) -> list[dict[str, Any]]:
    """List + fetch GuardDuty findings in a region. Returns raw finding dicts."""
    out: list[dict[str, Any]] = []
    try:
        client = assumed.client("guardduty", region)
        detectors = client.list_detectors().get("DetectorIds", [])
        for detector_id in detectors:
            ids = client.list_findings(DetectorId=detector_id).get("FindingIds", [])
            if not ids:
                continue
            resp = client.get_findings(DetectorId=detector_id, FindingIds=ids[:50])
            out.extend(resp.get("Findings", []))
    except Exception as exc:  # noqa: BLE001 - surfaced via source health, never raised
        logger.warning("poll_guardduty_failed", region=region, error=str(exc))
    return out


def poll_security_hub(assumed: Any, region: str) -> list[dict[str, Any]]:
    """Fetch recent Security Hub findings in a region (raw ASFF dicts)."""
    try:
        client = assumed.client("securityhub", region)
        return client.get_findings(MaxResults=50).get("Findings", [])
    except Exception as exc:  # noqa: BLE001
        logger.warning("poll_security_hub_failed", region=region, error=str(exc))
        return []


def poll_cloudtrail(assumed: Any, region: str) -> list[dict[str, Any]]:
    """Fetch recent CloudTrail management events in a region (raw event dicts)."""
    try:
        client = assumed.client("cloudtrail", region)
        return client.lookup_events(MaxResults=50).get("Events", [])
    except Exception as exc:  # noqa: BLE001
        logger.warning("poll_cloudtrail_failed", region=region, error=str(exc))
        return []
