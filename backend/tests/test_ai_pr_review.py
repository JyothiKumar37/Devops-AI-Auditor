"""M7 tests: AI-assisted PR review (advisory, grounded, non-authoritative)."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

import services.ai_pr_review_service as pr_review_mod
from agents.reasoning.llm import LLMMessage, LLMProvider, NullLLMProvider
from core.config import Settings
from core.database import Database
from models.pullrequest import PullRequest, PullRequestScan
from services.ai_pr_review_service import AiPrReviewService

FINDINGS_DETAIL = [
    {"rule_id": "K8S001", "severity": "high", "title": "No limits", "file": "k8s/deploy.yaml"},
    {"rule_id": "DCK001", "severity": "medium", "title": "root user", "file": "Dockerfile"},
]


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'prr.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )


@pytest.fixture
async def seeded(tmp_path: Path):
    settings = _settings(tmp_path)
    db = Database(settings)
    await db.create_all()
    pr_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    async with db.sessionmaker() as session:
        session.add(
            PullRequest(
                id=pr_id, provider="github", repo_full_name="acme/web", number=7,
                title="scale up", head_sha="abc",
            )
        )
        session.add(
            PullRequestScan(
                id=scan_id, pull_request_id=pr_id, head_sha="abc", status="completed",
                changed_files=2, new_findings=2, gate_status="fail",
                findings_detail=FINDINGS_DETAIL,
            )
        )
        await session.commit()
    yield db, settings, pr_id, scan_id
    await db.dispose()


class _ReviewProvider(LLMProvider):
    name = "rev"

    @property
    def available(self) -> bool:
        return True

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        return json.dumps(
            {
                "items": [
                    {
                        "title": "Replica increase may exceed DB pool",
                        "concern": "Scaling replicas without raising the connection pool.",
                        "category": "reliability",
                        "confidence": "medium",
                        "files": ["k8s/deploy.yaml", "ghost/not-real.yaml"],
                    },
                    {
                        "title": "Ungrounded item",
                        "concern": "references no real file",
                        "category": "security",
                        "confidence": "high",
                        "files": ["imaginary.txt"],
                    },
                ]
            }
        )


async def test_ai_disabled_returns_no_items(seeded) -> None:
    db, settings, _, scan_id = seeded
    async with db.sessionmaker() as session:
        monkey = AiPrReviewService(session, settings)
        monkey._provider = lambda: NullLLMProvider()  # type: ignore[method-assign]
        out = await monkey.review_pr_scan(scan_id)
    assert out["items"] == []
    assert out["authoritative"] is False


async def test_ai_review_grounded_and_labeled(seeded, monkeypatch: pytest.MonkeyPatch) -> None:
    db, settings, pr_id, scan_id = seeded
    monkeypatch.setattr(pr_review_mod, "get_provider", lambda s: _ReviewProvider())
    async with db.sessionmaker() as session:
        out = await AiPrReviewService(session, settings).review_pr_scan(scan_id)
    assert out["label"] == "AI Review"
    assert out["authoritative"] is False
    # The ungrounded item (no real file) was dropped; the grounded one kept.
    assert len(out["items"]) == 1
    item = out["items"][0]
    assert item["source"] == "AI_REVIEW"
    assert item["authoritative"] is False
    # The fake file inside the kept item was filtered out.
    assert item["files"] == ["k8s/deploy.yaml"]


async def test_review_pull_request_resolves_latest(seeded, monkeypatch: pytest.MonkeyPatch) -> None:
    db, settings, pr_id, _ = seeded
    monkeypatch.setattr(pr_review_mod, "get_provider", lambda s: _ReviewProvider())
    async with db.sessionmaker() as session:
        out = await AiPrReviewService(session, settings).review_pull_request(pr_id)
    assert out["label"] == "AI Review"
    assert len(out["items"]) == 1
