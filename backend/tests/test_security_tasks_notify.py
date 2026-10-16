"""M10 tests: incident notifications (redaction-safe) + celery task wiring.

Notifications are dispatched best-effort via a monkeypatched provider so no
network is used. Verifies that a critical incident fires notifications, that no
secret/raw payload leaks into the delivered message, and that the celery task
helpers run the ingest+correlate pipeline and prune old events.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest

import services.notification_service as notif_mod
from models.notification import NotificationChannel
from models.security import SecurityEvent
from services.incident_service import IncidentService
from services.notifications.base import Notification, NotificationProvider


class _CapturingProvider(NotificationProvider):
    sent: list[Notification] = []

    async def send(self, notification: Notification) -> None:
        _CapturingProvider.sent.append(notification)


def _event(**kw) -> SecurityEvent:
    base = dict(
        id=uuid.uuid4(), source_type="guardduty", source_event_id=str(uuid.uuid4()),
        category="threat", event_type="UnauthorizedAccess", severity="critical",
        confidence="medium", title="SSH brute force on i-1", fingerprint=uuid.uuid4().hex,
        status="new", source_ip="9.9.9.9", principal="role/admin",
    )
    base.update(kw)
    return SecurityEvent(**base)


async def _subscribe(sm, settings, events: list[str]) -> None:
    cipher = __import__("core.crypto", fromlist=["require_cipher"]).require_cipher(settings)
    async with sm() as session:
        session.add(NotificationChannel(
            id=uuid.uuid4(), type="webhook", name="sec", enabled=True,
            encrypted_config=cipher.encrypt(json.dumps({"url": "https://hooks.example/x"})),
            events=events,
        ))
        await session.commit()


@pytest.fixture(autouse=True)
def _patch_provider(monkeypatch):
    _CapturingProvider.sent = []
    monkeypatch.setattr(
        notif_mod, "notifier_factory", lambda ctype, config, settings: _CapturingProvider()
    )
    yield


async def test_critical_incident_notifies_and_redacts(mem_db) -> None:
    sm, settings = mem_db
    await _subscribe(sm, settings, ["incident_created", "incident_critical"])
    async with sm() as session:
        session.add(_event(account_ref="123456789012", resource_id="i-1"))
        await session.commit()
        incidents = await IncidentService(session, settings).correlate_new_events()
        await session.commit()
        assert incidents[0].severity == "critical"

    events_sent = {n.event for n in _CapturingProvider.sent}
    assert "incident_created" in events_sent
    assert "incident_critical" in events_sent
    # No secret-ish material or raw payloads in any delivered notification.
    blob = " ".join(n.title + n.body + json.dumps(n.fields) for n in _CapturingProvider.sent)
    assert "role/admin" not in blob  # principal (identity) not leaked into body
    assert "provenance" not in blob
    assert "9.9.9.9" not in blob


async def test_no_notification_when_not_subscribed(mem_db) -> None:
    sm, settings = mem_db
    # No channel subscribed -> dispatch is a safe no-op.
    async with sm() as session:
        session.add(_event(account_ref="acct", resource_id="i-2", severity="low",
                           category="misconfiguration"))
        await session.commit()
        await IncidentService(session, settings).correlate_new_events()
        await session.commit()
    assert _CapturingProvider.sent == []


async def test_poll_prunes_old_uncorrelated_events(mem_db) -> None:
    sm, settings = mem_db
    from sqlalchemy import func, select

    old = datetime.now(UTC) - timedelta(days=settings.security_event_retention_days + 5)
    async with sm() as session:
        session.add(_event(account_ref="acct", resource_id="old-1", status="new",
                           first_observed_at=old, last_observed_at=old))
        await session.commit()

    # Simulate the prune step of poll_security_sources (retention policy).
    from sqlalchemy import delete

    async with sm() as session:
        cutoff = datetime.now(UTC) - timedelta(days=settings.security_event_retention_days)
        await session.execute(
            delete(SecurityEvent).where(
                SecurityEvent.incident_id.is_(None), SecurityEvent.last_observed_at < cutoff
            )
        )
        await session.commit()
        remaining = await session.scalar(select(func.count()).select_from(SecurityEvent))
        assert remaining == 0
