"""M5 tests: AI investigation endpoints (scan/finding/repository scoped).

Default runs with AI disabled (deterministic fallback). One test monkeypatches a
scripted provider to exercise the full tool-grounded path through the API.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import agents.investigation.engine as engine_mod
from agents.reasoning.llm import LLMMessage, LLMProvider
from core.config import Settings
from core.database import Database
from main import create_app
from models.enums import Confidence, FindingCategory, Severity
from models.finding import Finding
from models.scan import RepositoryFile, Scan

SCAN_ID = uuid.uuid4()
FILE_ID = uuid.uuid4()
FINDING_ID = uuid.uuid4()


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'api.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )


async def _seed(db: Database) -> None:
    await db.create_all()
    async with db.sessionmaker() as session:
        session.add(
            Scan(id=SCAN_ID, repository_name="acme/web", source_type="zip", status="completed")
        )
        session.add(
            RepositoryFile(
                id=FILE_ID, scan_id=SCAN_ID, path="k8s/deploy.yaml", file_type="other",
                size=10, checksum="x" * 64, content="a\nb\n",
            )
        )
        session.add(
            Finding(
                id=FINDING_ID, scan_id=SCAN_ID, file_id=FILE_ID,
                category=FindingCategory.RELIABILITY, severity=Severity.HIGH,
                confidence=Confidence.HIGH, title="Missing limits", description="d",
                evidence="e", recommendation="add limits", line_number=1,
                rule_id="K8S001", scanner="kubernetes-rules",
            )
        )
        await session.commit()


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    import asyncio

    settings = _settings(tmp_path)

    async def _prepare() -> None:
        db = Database(settings)
        await _seed(db)
        await db.dispose()

    asyncio.run(_prepare())
    with TestClient(create_app(settings=settings)) as c:
        yield c


def test_scan_investigation_fallback(client: TestClient) -> None:
    resp = client.post(
        f"/api/v1/ai/scans/{SCAN_ID}/investigate",
        json={"question": "What are the biggest risks?"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["label"] == "AI Insight"
    assert body["ai_used"] is False  # no provider configured
    assert "answer" in body


def test_finding_investigation_fallback(client: TestClient) -> None:
    resp = client.post(
        f"/api/v1/ai/scans/{SCAN_ID}/findings/{FINDING_ID}/investigate",
        json={"question": "Is this dangerous?"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["label"] == "AI Insight"


def test_repository_investigation_fallback(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/ai/repository/investigate",
        json={"repository": "acme/web", "question": "top risks?"},
    )
    assert resp.status_code == 200, resp.text


def test_unknown_scan_404(client: TestClient) -> None:
    resp = client.post(
        f"/api/v1/ai/scans/{uuid.uuid4()}/investigate",
        json={"question": "anything"},
    )
    assert resp.status_code == 404


def test_unknown_repository_404(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/ai/repository/investigate",
        json={"repository": "nope/missing", "question": "x"},
    )
    assert resp.status_code == 404


class _Scripted(LLMProvider):
    name = "scripted"

    def __init__(self) -> None:
        self._decided = False

    @property
    def available(self) -> bool:
        return True

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        system = messages[0].content
        if "investigation planner" in system:
            return json.dumps({"intent": "risks", "plan": []})
        if "investigation agent" in system:
            if not self._decided:
                self._decided = True
                return json.dumps(
                    {
                        "action": "call_tool", "tool": "get_findings",
                        "tool_args": {"scan_id": str(SCAN_ID)}, "purpose": "list",
                    }
                )
            return json.dumps({"action": "final"})
        return json.dumps(
            {
                "answer": "The deployment is missing resource limits.",
                "root_cause": "no resource management",
                "cited_finding_ids": [str(FINDING_ID)],
                "cited_files": ["k8s/deploy.yaml"],
            }
        )


def test_investigation_is_persisted_and_listable(client: TestClient) -> None:
    created = client.post(
        f"/api/v1/ai/scans/{SCAN_ID}/investigate",
        json={"question": "What are the biggest risks?"},
    ).json()
    inv_id = created["investigation_id"]
    assert inv_id

    listing = client.get(f"/api/v1/ai/investigations?scan_id={SCAN_ID}").json()
    assert listing["total"] >= 1
    assert any(item["id"] == inv_id for item in listing["items"])

    detail = client.get(f"/api/v1/ai/investigations/{inv_id}").json()
    assert detail["id"] == inv_id
    assert detail["scope"] == "scan"
    assert "trace" in detail and "evidence" in detail


def test_get_unknown_investigation_404(client: TestClient) -> None:
    resp = client.get(f"/api/v1/ai/investigations/{uuid.uuid4()}")
    assert resp.status_code == 404


def test_scan_investigation_with_ai(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod, "get_provider", lambda settings: _Scripted())
    resp = client.post(
        f"/api/v1/ai/scans/{SCAN_ID}/investigate",
        json={"question": "Why is reliability low?"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ai_used"] is True
    assert body["tool_calls"] >= 1
    assert str(FINDING_ID) in body["cited_finding_ids"]
    assert body["confidence"] in {"low", "medium", "high"}
    assert any(e["tool"] == "get_findings" for e in body["evidence"])
