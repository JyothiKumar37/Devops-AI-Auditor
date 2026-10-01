"""End-to-end Phase 2 flow with fakes (no network, no live git, no celery):

    webhook (validate + dedup + dispatch)
      -> incremental PR scan (deterministic engine)
      -> policy evaluation (gate)
      -> PR feedback (summary comment + commit status)
      -> notification dispatch (pr_scan_failed)

The webhook link is proven by capturing the dispatch call; the downstream chain
is then executed in-process the way the Celery task would run it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

import services.notification_service as notif_mod
import services.pr_feedback_service as pr_feedback_service
from core.config import Settings
from core.crypto import TokenCipher
from core.database import Database
from models.integration import SCMIntegration
from models.notification import NotificationDelivery
from models.pullrequest import PullRequest, PullRequestScan, WebhookEvent
from services.notification_service import NotificationService
from services.notifications import Notification
from services.policy_service import PolicyService
from services.pr_feedback_service import PRFeedbackService
from services.pr_scan_service import PRScanService
from services.scm.base import ChangeStatus, SCMChangedFile
from services.scm.fake import FakeSCMProvider, make_pr, make_repo
from services.webhook_service import WebhookService

SECRET = "whsec-e2e"

VULN_K8S = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 1
  selector:
    matchLabels: {app: api}
  template:
    metadata: {labels: {app: api}}
    spec:
      containers:
        - name: api
          image: myrepo/api:latest
          securityContext:
            privileged: true
"""

POLICY_YAML = """\
version: 1
name: global-gate
rules:
  - id: block-high
    condition:
      severity: high
    action: fail
  - id: block-critical
    condition:
      severity: critical
    action: fail
"""

WEBHOOK_PAYLOAD = {
    "action": "synchronize",
    "number": 7,
    "repository": {"id": 99, "full_name": "acme/web"},
    "pull_request": {"number": 7, "head": {"sha": "head7", "ref": "feat"}, "base": {"ref": "main"}},
}


def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()


def _clone_writes(files: dict[str, str]):
    def _clone(url: str, ref: str | None, dest: Path) -> None:
        for rel, content in files.items():
            p = dest / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
    return _clone


class _RecordingProvider:
    """A notification provider that records every delivered notification."""

    sent: list[Notification] = []

    async def send(self, notification: Notification) -> None:
        _RecordingProvider.sent.append(notification)


@pytest.fixture
async def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    key = Fernet.generate_key().decode()
    settings = Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'e2e.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
        integration_encryption_key=key,
        github_webhook_secret=SECRET,
        notifications_allow_private_hosts=True,
    )
    database = Database(settings)
    await database.create_all()

    # Fake SCM provider used for both webhook parsing and PR feedback posting.
    provider = FakeSCMProvider()
    repo = make_repo("acme", "web")
    provider.add_repo(repo)
    provider.add_pr(
        repo, make_pr(7, head_sha="head7"),
        [SCMChangedFile(path="k8s/app.yaml", status=ChangeStatus.ADDED)],
    )
    monkeypatch.setattr(pr_feedback_service, "provider_factory", lambda n, t, s: provider)

    # Notifications go to a recording fake (no network).
    _RecordingProvider.sent.clear()
    monkeypatch.setattr(notif_mod, "notifier_factory", lambda t, c, s: _RecordingProvider())

    async with database.sessionmaker() as session:
        session.add(
            SCMIntegration(
                id=uuid.uuid4(), provider="github", account="acme", name="gh",
                status="connected", api_url="https://api.github.com",
                encrypted_token=TokenCipher(key).encrypt("ghp_tok"),
            )
        )
        await session.flush()
        integration_id = (await session.scalars(select(SCMIntegration))).first().id

        # A global policy that fails on new high/critical findings.
        policy_service = PolicyService(session)
        policy = await policy_service.create("global-gate", POLICY_YAML)
        await policy_service.assign(policy.id, "global")

        # A webhook notification channel subscribed to PR gate failures.
        await NotificationService(session, settings).create(
            "webhook", "sec-alerts",
            {"url": "https://alerts.example.com/hook"}, ["pr_scan_failed"],
        )
        await session.commit()

    return database, settings, provider, integration_id


async def test_full_pipeline(env) -> None:
    database, settings, provider, integration_id = env
    body = json.dumps(WEBHOOK_PAYLOAD).encode()
    headers = {
        "x-hub-signature-256": _sign(body),
        "x-github-event": "pull_request",
        "x-github-delivery": "e2e-1",
    }

    # 1) Webhook: validate signature, persist event, route to dispatch.
    captured: list[tuple] = []
    async with database.sessionmaker() as session:
        service = WebhookService(
            session, settings,
            dispatch_fn=lambda p, iid, repo, pr: captured.append((p, iid, repo, pr)),
        )
        result = await service.handle("github", headers, body)
        await session.commit()

    assert result["status"] == "accepted"
    assert result["scan_dispatched"] is True
    assert captured == [("github", integration_id, "acme/web", 7)]

    # WebhookEvent persisted for idempotency.
    async with database.sessionmaker() as session:
        events = (await session.scalars(select(WebhookEvent))).all()
        assert len(events) == 1
        assert events[0].delivery_id == "e2e-1"

    # 2-4) Run the dispatched work the way the Celery task would.
    provider_name, iid, repo_full_name, pr_number = captured[0]
    async with database.sessionmaker() as session:
        feedback = PRFeedbackService(
            session=session,
            settings=settings,
            scan_service=PRScanService(
                session, settings, clone_fn=_clone_writes({"k8s/app.yaml": VULN_K8S})
            ),
        )
        pr_scan = await feedback.scan_and_report(provider_name, iid, repo_full_name, pr_number)
        await session.commit()

    # Deterministic scan produced new findings and the policy failed the gate.
    assert pr_scan.new_findings > 0
    assert pr_scan.gate_status == "fail"
    assert pr_scan.policy_result is not None
    assert pr_scan.policy_result.get("violations")

    # PR feedback posted a summary comment and a failing commit status.
    comments = provider.comments[("acme/web", 7)]
    assert len(comments) == 1
    assert provider.statuses[-1]["state"] == "failure"

    # Persisted PR + scan.
    async with database.sessionmaker() as session:
        pr = (await session.scalars(select(PullRequest))).first()
        assert pr is not None and pr.number == 7
        scans = (await session.scalars(select(PullRequestScan))).all()
        assert len(scans) == 1

        # 5) Notification dispatched for the failed gate and recorded as sent.
        deliveries = (await session.scalars(select(NotificationDelivery))).all()
        pr_failed = [d for d in deliveries if d.event_type == "pr_scan_failed"]
        assert pr_failed and pr_failed[0].status == "sent"

    assert any(n.event == "pr_scan_failed" for n in _RecordingProvider.sent)
    await database.dispose()
