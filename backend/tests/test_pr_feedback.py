"""Tests for PR feedback: summary comment reconciliation + commit status."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

import services.pr_feedback_service as pr_feedback_service
from core.config import Settings
from core.crypto import TokenCipher
from core.database import Database
from models.integration import SCMIntegration
from services.pr_feedback_service import COMMENT_MARKER, PRFeedbackService
from services.scm.base import ChangeStatus, SCMChangedFile
from services.scm.fake import FakeSCMProvider, make_pr, make_repo

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


def _settings(tmp_path: Path, key: str) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'fb.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
        integration_encryption_key=key,
    )


def _clone_writes(files: dict[str, str]):
    def _clone(url: str, ref: str | None, dest: Path) -> None:
        for rel, content in files.items():
            p = dest / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
    return _clone


@pytest.fixture
async def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    key = Fernet.generate_key().decode()
    settings = _settings(tmp_path, key)
    database = Database(settings)
    await database.create_all()

    provider = FakeSCMProvider()
    repo = make_repo("acme", "web")
    provider.add_repo(repo)
    provider.add_pr(
        repo, make_pr(1, head_sha="head1"),
        [SCMChangedFile(path="k8s/app.yaml", status=ChangeStatus.ADDED)],
    )
    monkeypatch.setattr(pr_feedback_service, "provider_factory", lambda n, t, s: provider)

    # Seed a connected integration (encrypted token).
    async with database.sessionmaker() as session:
        session.add(
            SCMIntegration(
                id=uuid.uuid4(), provider="github", account="acme", name="gh",
                status="connected", api_url="https://api.github.com",
                encrypted_token=TokenCipher(key).encrypt("ghp_tok"),
            )
        )
        await session.commit()
        integration_id = (
            await session.scalars(__import__("sqlalchemy").select(SCMIntegration))
        ).first().id
    return database, settings, provider, integration_id


async def _run(database: Database, settings: Settings, integration_id: uuid.UUID):
    async with database.sessionmaker() as session:
        feedback = PRFeedbackService(
            session=session, settings=settings,
            scan_service=__import__(
                "services.pr_scan_service", fromlist=["PRScanService"]
            ).PRScanService(session, settings, clone_fn=_clone_writes({"k8s/app.yaml": VULN_K8S})),
        )
        result = await feedback.scan_and_report(
            "github", integration_id, "acme/web", 1
        )
        await session.commit()
        return result


async def test_posts_summary_comment_and_status(setup) -> None:
    database, settings, provider, integration_id = setup
    await _run(database, settings, integration_id)

    comments = provider.comments[("acme/web", 1)]
    assert len(comments) == 1
    assert COMMENT_MARKER in comments[0].body
    assert "PR Security Analysis" in comments[0].body
    # A privileged container -> gate fail -> failure status set.
    assert provider.statuses[-1]["state"] == "failure"
    assert provider.statuses[-1]["context"] == "devops-ai-auditor"
    await database.dispose()


async def test_comment_is_reconciled_not_duplicated(setup) -> None:
    database, settings, provider, integration_id = setup
    await _run(database, settings, integration_id)
    first_body = provider.comments[("acme/web", 1)][0].body
    # Second scan of the same PR must UPDATE the existing comment, not add one.
    await _run(database, settings, integration_id)
    comments = provider.comments[("acme/web", 1)]
    assert len(comments) == 1, "summary comment must be reconciled, not duplicated"
    assert COMMENT_MARKER in comments[0].body
    # Two statuses were set (one per scan).
    assert len(provider.statuses) == 2
    assert first_body  # sanity
    await database.dispose()
