"""Notification abstraction: event types, payload, provider interface, SSRF guard.

Providers (Slack/Teams/Webhook/Email) implement ``NotificationProvider.send``.
All HTTP-based providers must route outbound URLs through ``ensure_public_url``
to prevent SSRF against internal/loopback addresses.
"""

from __future__ import annotations

import abc
import ipaddress
import socket
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit


class NotificationError(Exception):
    """Delivering a notification failed (never fatal to the triggering scan)."""


class NotificationEvent(str, Enum):
    """Events a channel can subscribe to."""

    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    CRITICAL_FINDING = "critical_finding"
    SECRET_DETECTED = "secret_detected"
    POLICY_FAILED = "policy_failed"
    PR_SCAN_FAILED = "pr_scan_failed"
    READINESS_DECREASED = "readiness_decreased"
    NEW_VULNERABILITY = "new_vulnerability"
    REMEDIATION_COMPLETED = "remediation_completed"


ALL_EVENTS = [e.value for e in NotificationEvent]


@dataclass(frozen=True, slots=True)
class Notification:
    """A provider-agnostic message to deliver."""

    event: str
    title: str
    body: str
    severity: str = "info"
    link: str | None = None
    fields: dict[str, str] = field(default_factory=dict)


def ensure_public_url(url: str, *, allow_private: bool) -> str:
    """Validate an outbound URL is https(s) and not pointing at a private host.

    Guards against SSRF: resolves the host and rejects loopback/private/link-local
    /reserved addresses unless explicitly allowed (test/dev only).
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise NotificationError(f"Unsupported URL scheme '{parts.scheme}'.")
    host = parts.hostname
    if not host:
        raise NotificationError("URL has no host.")
    if allow_private:
        return url
    try:
        infos = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80))
    except OSError as exc:
        raise NotificationError(f"Could not resolve host '{host}'.") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
            raise NotificationError(
                f"Refusing to send to a private/loopback address ({ip})."
            )
    return url


class NotificationProvider(abc.ABC):
    """Delivers a single notification to one configured destination."""

    @abc.abstractmethod
    async def send(self, notification: Notification) -> None: ...
