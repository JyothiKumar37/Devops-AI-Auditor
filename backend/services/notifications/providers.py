"""Concrete notification providers: Slack, Teams, generic Webhook, Email.

HTTP providers accept an optional httpx transport so tests can inject a
``MockTransport`` without real network access. All outbound URLs pass through
``ensure_public_url`` to prevent SSRF.
"""

from __future__ import annotations

import asyncio
import smtplib
from email.message import EmailMessage

import httpx

from core.config import Settings
from services.notifications.base import (
    Notification,
    NotificationError,
    NotificationProvider,
    ensure_public_url,
)

_TIMEOUT = 10.0


def _severity_emoji(severity: str) -> str:
    return {
        "critical": "\U0001f534",
        "high": "\U0001f7e0",
        "medium": "\U0001f7e1",
        "low": "\U0001f535",
        "info": "\u2139\ufe0f",
    }.get(severity.lower(), "\u2139\ufe0f")


class _HttpProvider(NotificationProvider):
    """Base for webhook-style providers that POST JSON to a URL."""

    def __init__(
        self,
        url: str,
        *,
        allow_private: bool,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = ensure_public_url(url, allow_private=allow_private)
        self._transport = transport

    async def _post(self, payload: dict) -> None:
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=_TIMEOUT
            ) as client:
                resp = await client.post(self._url, json=payload)
                resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise NotificationError(f"HTTP delivery failed: {exc}") from exc

    async def send(self, notification: Notification) -> None:  # pragma: no cover
        raise NotImplementedError


class SlackProvider(_HttpProvider):
    """Posts to a Slack Incoming Webhook URL."""

    async def send(self, notification: Notification) -> None:
        emoji = _severity_emoji(notification.severity)
        lines = [f"{emoji} *{notification.title}*", notification.body]
        for key, value in notification.fields.items():
            lines.append(f"*{key}:* {value}")
        if notification.link:
            lines.append(f"<{notification.link}|View details>")
        await self._post({"text": "\n".join(line for line in lines if line)})


class TeamsProvider(_HttpProvider):
    """Posts a MessageCard to a Microsoft Teams Incoming Webhook URL."""

    async def send(self, notification: Notification) -> None:
        facts = [{"name": k, "value": v} for k, v in notification.fields.items()]
        card: dict = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": notification.title,
            "themeColor": self._theme(notification.severity),
            "sections": [
                {
                    "activityTitle": notification.title,
                    "text": notification.body,
                    "facts": facts,
                }
            ],
        }
        if notification.link:
            card["potentialAction"] = [
                {
                    "@type": "OpenUri",
                    "name": "View details",
                    "targets": [{"os": "default", "uri": notification.link}],
                }
            ]
        await self._post(card)

    @staticmethod
    def _theme(severity: str) -> str:
        return {
            "critical": "D13438",
            "high": "E8630A",
            "medium": "F2C811",
            "low": "0078D4",
            "info": "6B6B6B",
        }.get(severity.lower(), "6B6B6B")


class WebhookProvider(_HttpProvider):
    """Posts a structured JSON payload to an arbitrary webhook URL."""

    async def send(self, notification: Notification) -> None:
        await self._post(
            {
                "event": notification.event,
                "title": notification.title,
                "body": notification.body,
                "severity": notification.severity,
                "link": notification.link,
                "fields": notification.fields,
            }
        )


class EmailProvider(NotificationProvider):
    """Sends email via SMTP using stdlib smtplib (run off the event loop)."""

    def __init__(self, recipients: list[str], settings: Settings) -> None:
        if not recipients:
            raise NotificationError("Email channel requires at least one recipient.")
        if not settings.smtp_host:
            raise NotificationError("SMTP is not configured (set SMTP_HOST).")
        self._recipients = recipients
        self._settings = settings

    async def send(self, notification: Notification) -> None:
        await asyncio.to_thread(self._send_sync, notification)

    def _send_sync(self, notification: Notification) -> None:
        s = self._settings
        msg = EmailMessage()
        msg["Subject"] = f"[{notification.severity.upper()}] {notification.title}"
        msg["From"] = s.smtp_from or (s.smtp_username or "devops-ai-auditor@localhost")
        msg["To"] = ", ".join(self._recipients)
        body = notification.body
        for key, value in notification.fields.items():
            body += f"\n{key}: {value}"
        if notification.link:
            body += f"\n\nDetails: {notification.link}"
        msg.set_content(body)
        try:
            with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=_TIMEOUT) as server:
                if s.smtp_use_tls:
                    server.starttls()
                if s.smtp_username:
                    server.login(s.smtp_username, s.smtp_password or "")
                server.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise NotificationError(f"SMTP delivery failed: {exc}") from exc
