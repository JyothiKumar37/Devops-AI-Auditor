"""Tests for notifications: SSRF guard, channel CRUD/masking, dispatch routing.

Dispatch is best-effort - delivery failures must be recorded and swallowed, never
raised. The provider factory is monkeypatched with a fake so no network is used.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import services.notification_service as notif_mod
from core.config import Settings
from core.database import Database
from core.exceptions import ValidationError
from main import create_app
from services.notification_service import NotificationService
from services.notifications import Notification, NotificationError
from services.notifications.base import ensure_public_url

FERNET_KEY = Fernet.generate_key().decode()


def _settings(tmp_path: Path, *, allow_private: bool = True) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'notif.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
        integration_encryption_key=FERNET_KEY,
        notifications_allow_private_hosts=allow_private,
    )


@pytest.fixture
async def db(tmp_path: Path) -> Database:
    database = Database(_settings(tmp_path))
    await database.create_all()
    return database


class _FakeProvider:
    """Records sends; optionally raises to simulate a delivery failure."""

    instances: list[_FakeProvider] = []

    def __init__(self, *, fail: bool = False) -> None:
        self.sent: list[Notification] = []
        self.fail = fail
        _FakeProvider.instances.append(self)

    async def send(self, notification: Notification) -> None:
        if self.fail:
            raise NotificationError("boom")
        self.sent.append(notification)


# ---- SSRF guard -------------------------------------------------------------


def test_ssrf_guard_rejects_loopback() -> None:
    with pytest.raises(NotificationError):
        ensure_public_url("http://localhost:9000/hook", allow_private=False)


def test_ssrf_guard_rejects_private_range() -> None:
    with pytest.raises(NotificationError):
        ensure_public_url("http://10.0.0.5/hook", allow_private=False)


def test_ssrf_guard_rejects_non_http_scheme() -> None:
    with pytest.raises(NotificationError):
        ensure_public_url("file:///etc/passwd", allow_private=False)


def test_ssrf_guard_allows_private_when_configured() -> None:
    # When explicitly allowed (dev/test), private hosts are permitted.
    assert ensure_public_url("http://10.0.0.5/hook", allow_private=True)


# ---- Channel CRUD + masking -------------------------------------------------


async def test_create_and_mask_secret(db: Database) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    async with db.sessionmaker() as session:
        service = NotificationService(session, settings)
        channel = await service.create(
            "slack",
            "team-sec",
            {"webhook_url": "https://hooks.slack.com/services/XXXX/secret-token"},
            ["scan_failed"],
        )
        masked = service.masked_config(channel)
        assert "secret-token" not in str(masked)
        assert masked["webhook_url"].startswith("***")


async def test_create_rejects_unknown_type(db: Database) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    async with db.sessionmaker() as session:
        service = NotificationService(session, settings)
        with pytest.raises(ValidationError):
            await service.create("pager", "x", {}, ["scan_failed"])


async def test_create_rejects_no_valid_events(db: Database) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    async with db.sessionmaker() as session:
        service = NotificationService(session, settings)
        with pytest.raises(ValidationError):
            await service.create(
                "slack", "x", {"webhook_url": "https://hooks.slack.com/y"}, ["nope"]
            )


# ---- Dispatch routing + failure swallow -------------------------------------


async def test_dispatch_routes_only_to_subscribed(
    db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    _FakeProvider.instances.clear()
    fakes: dict[str, _FakeProvider] = {}

    def _factory(channel_type, config, settings):  # noqa: ANN001
        fp = _FakeProvider()
        fakes[config.get("tag", "")] = fp
        return fp

    monkeypatch.setattr(notif_mod, "notifier_factory", _factory)

    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    async with db.sessionmaker() as session:
        service = NotificationService(session, settings)
        await service.create(
            "webhook", "subscribed",
            {"url": "https://example.com/a", "tag": "sub"}, ["scan_failed"],
        )
        await service.create(
            "webhook", "other",
            {"url": "https://example.com/b", "tag": "other"}, ["scan_completed"],
        )

        deliveries = await service.dispatch(
            "scan_failed",
            Notification(event="scan_failed", title="t", body="b", severity="high"),
        )
        assert len(deliveries) == 1
        assert deliveries[0].status == "sent"


async def test_dispatch_failure_is_swallowed(
    db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _factory(channel_type, config, settings):  # noqa: ANN001
        return _FakeProvider(fail=True)

    monkeypatch.setattr(notif_mod, "notifier_factory", _factory)

    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    async with db.sessionmaker() as session:
        service = NotificationService(session, settings)
        await service.create(
            "webhook", "willfail",
            {"url": "https://example.com/a"}, ["scan_failed"],
        )
        # Must not raise.
        deliveries = await service.dispatch(
            "scan_failed", Notification(event="scan_failed", title="t", body="b")
        )
        assert len(deliveries) == 1
        assert deliveries[0].status == "failed"
        assert deliveries[0].error == "boom"


async def test_test_send_records_delivery(
    db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        notif_mod, "notifier_factory", lambda t, c, s: _FakeProvider()
    )
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    async with db.sessionmaker() as session:
        service = NotificationService(session, settings)
        channel = await service.create(
            "webhook", "c", {"url": "https://example.com/a"}, ["scan_failed"]
        )
        delivery = await service.test(channel.id)
        assert delivery.status == "sent"
        assert delivery.event_type == "test"


# ---- API: SSRF rejection through create ------------------------------------


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = _settings(tmp_path, allow_private=False)
    with TestClient(create_app(settings=settings)) as c:
        yield c


def test_api_rejects_private_webhook_url(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/notifications",
        json={
            "type": "webhook",
            "name": "bad",
            "config": {"url": "http://localhost:9000/hook"},
            "events": ["scan_failed"],
        },
    )
    assert resp.status_code == 422
