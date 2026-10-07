"""M8 tests: AI security review agent (targeted, grounded, non-authoritative)."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

import services.ai_security_review_service as sec_mod
from agents.reasoning.llm import LLMMessage, LLMProvider
from core.config import Settings
from core.database import Database
from core.exceptions import NotFoundError
from models.enums import Confidence, FindingCategory, Severity
from models.finding import Finding
from models.scan import RepositoryFile, Scan


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'sec.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )


@pytest.fixture
async def seeded(tmp_path: Path):
    settings = _settings(tmp_path)
    db = Database(settings)
    await db.create_all()
    scan_id = uuid.uuid4()
    file_id = uuid.uuid4()
    async with db.sessionmaker() as session:
        session.add(
            Scan(id=scan_id, repository_name="acme/web", source_type="zip", status="completed")
        )
        session.add(
            RepositoryFile(
                id=file_id, scan_id=scan_id, path="k8s/ingress.yaml", file_type="kubernetes",
                size=10, checksum="x" * 64, content="a\nb\n",
            )
        )
        session.add(
            Finding(
                id=uuid.uuid4(), scan_id=scan_id, file_id=file_id,
                category=FindingCategory.SECURITY, severity=Severity.HIGH,
                confidence=Confidence.HIGH, title="Public ingress", description="d",
                evidence="e", recommendation="restrict", line_number=1,
                rule_id="K8S010", scanner="kubernetes-rules",
            )
        )
        await session.commit()
    yield db, settings, scan_id
    await db.dispose()


class _SecProvider(LLMProvider):
    name = "sec"

    @property
    def available(self) -> bool:
        return True

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        return json.dumps(
            {
                "items": [
                    {
                        "title": "Public ingress without authentication layer",
                        "concern": "Ingress exposes the service with no auth in front.",
                        "category": "security",
                        "confidence": "medium",
                        "files": ["k8s/ingress.yaml"],
                    }
                ]
            }
        )


async def test_security_review_disabled(seeded) -> None:
    db, settings, scan_id = seeded
    async with db.sessionmaker() as session:
        out = await sec_mod.AiSecurityReviewService(session, settings).review_scan(scan_id)
    assert out["items"] == []
    assert out["authoritative"] is False
    assert out["scan_id"] == str(scan_id)


async def test_security_review_grounded(seeded, monkeypatch: pytest.MonkeyPatch) -> None:
    db, settings, scan_id = seeded
    monkeypatch.setattr(sec_mod, "get_provider", lambda s: _SecProvider())
    async with db.sessionmaker() as session:
        out = await sec_mod.AiSecurityReviewService(session, settings).review_scan(scan_id)
    assert out["label"] == "AI Security Review"
    assert len(out["items"]) == 1
    item = out["items"][0]
    assert item["source"] == "AI_REVIEW"
    assert item["authoritative"] is False
    assert item["files"] == ["k8s/ingress.yaml"]


async def test_security_review_unknown_scan(seeded) -> None:
    db, settings, _ = seeded
    async with db.sessionmaker() as session:
        with pytest.raises(NotFoundError):
            await sec_mod.AiSecurityReviewService(session, settings).review_scan(uuid.uuid4())
