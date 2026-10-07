"""M3 tests: citation verification, deterministic confidence, insufficient-evidence."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from agents.investigation.engine import InvestigationEngine
from agents.investigation.verification import (
    INSUFFICIENT_EVIDENCE_MESSAGE,
    compute_confidence,
    verify_citations,
)
from agents.reasoning.llm import LLMMessage, LLMProvider
from core.config import Settings
from core.database import Database
from models.enums import Confidence, FindingCategory, Severity
from models.finding import Finding
from models.scan import RepositoryFile, Scan

# ---- verification unit tests ----------------------------------------------


def test_verify_citations_drops_unseen() -> None:
    check = verify_citations(
        cited_finding_ids=["a", "b", "ghost"],
        cited_files=["real.yaml", "fake.yaml"],
        seen_finding_ids={"a", "b"},
        seen_files={"real.yaml"},
    )
    assert check.verified_finding_ids == ["a", "b"]
    assert check.verified_files == ["real.yaml"]
    assert check.dropped_finding_ids == ["ghost"]
    assert check.dropped_files == ["fake.yaml"]
    assert check.had_hallucination is True
    assert check.has_verified_evidence is True


def test_confidence_tiers() -> None:
    high = verify_citations(["a", "b"], ["f.yaml"], {"a", "b"}, {"f.yaml"})
    assert compute_confidence(high, tool_calls=2, ai_used=True) == "high"

    medium = verify_citations(["a"], [], {"a"}, set())
    assert compute_confidence(medium, tool_calls=1, ai_used=True) == "medium"

    low = verify_citations([], [], set(), set())
    assert compute_confidence(low, tool_calls=1, ai_used=True) == "low"

    # AI unavailable is always low confidence regardless of evidence.
    assert compute_confidence(high, tool_calls=5, ai_used=False) == "low"


# ---- engine-level safeguards ----------------------------------------------


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'safe.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )


@pytest.fixture
async def ctx(tmp_path: Path):
    settings = _settings(tmp_path)
    db = Database(settings)
    await db.create_all()
    scan_id = uuid.uuid4()
    file_id = uuid.uuid4()
    fids = [uuid.uuid4(), uuid.uuid4()]
    async with db.sessionmaker() as session:
        session.add(
            Scan(id=scan_id, repository_name="acme/web", source_type="zip", status="completed")
        )
        session.add(
            RepositoryFile(
                id=file_id, scan_id=scan_id, path="k8s/deploy.yaml", file_type="other",
                size=10, checksum="x" * 64, content="a\nb\n",
            )
        )
        for i, fid in enumerate(fids):
            session.add(
                Finding(
                    id=fid, scan_id=scan_id, file_id=file_id,
                    category=FindingCategory.RELIABILITY,
                    severity=Severity.HIGH if i == 0 else Severity.MEDIUM,
                    confidence=Confidence.HIGH, title=f"K8s issue {i}", description="d",
                    evidence="e", recommendation="fix", line_number=i + 1,
                    rule_id=f"K8S{i}", scanner="kubernetes-rules",
                )
            )
        await session.commit()
    yield db, settings, scan_id, [str(f) for f in fids]
    await db.dispose()


class _Provider(LLMProvider):
    name = "fake"

    def __init__(self, scan_id: str, final_payload: dict, *, call_tool: bool = True) -> None:
        self._scan_id = scan_id
        self._final = final_payload
        self._call_tool = call_tool
        self._decided = False

    @property
    def available(self) -> bool:
        return True

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        system = messages[0].content
        if "investigation planner" in system:
            return json.dumps({"intent": "x", "plan": []})
        if "investigation agent" in system:
            if self._call_tool and not self._decided:
                self._decided = True
                return json.dumps(
                    {
                        "action": "call_tool", "tool": "get_findings",
                        "tool_args": {"scan_id": self._scan_id}, "purpose": "list",
                    }
                )
            return json.dumps({"action": "final"})
        return json.dumps(self._final)


async def test_high_confidence_with_verified_evidence(ctx) -> None:
    db, settings, scan_id, fids = ctx
    final = {
        "answer": "Two reliability findings in k8s/deploy.yaml.",
        "root_cause": "missing resource management",
        "impact": "restarts",
        "recommendations": ["add limits"],
        "cited_finding_ids": fids,  # both real
        "cited_files": ["k8s/deploy.yaml"],
    }
    provider = _Provider(str(scan_id), final, call_tool=True)
    async with db.sessionmaker() as session:
        engine = await InvestigationEngine.build(
            session, settings, scan_id=scan_id, provider=provider
        )
        result = await engine.investigate("why unreliable?")
    assert set(result.cited_finding_ids) == set(fids)
    assert result.cited_files == ["k8s/deploy.yaml"]
    assert result.confidence == "high"
    assert result.hallucination_guard_triggered is False
    assert result.label == "AI Insight"
    assert any(c["type"] == "finding" for c in result.citations)


async def test_hallucinated_citation_is_dropped(ctx) -> None:
    db, settings, scan_id, fids = ctx
    ghost = str(uuid.uuid4())
    final = {
        "answer": "claims a finding that was never retrieved",
        "cited_finding_ids": [ghost],
        "cited_files": ["does/not/exist.yaml"],
    }
    provider = _Provider(str(scan_id), final, call_tool=True)
    async with db.sessionmaker() as session:
        engine = await InvestigationEngine.build(
            session, settings, scan_id=scan_id, provider=provider
        )
        result = await engine.investigate("make something up")
    assert ghost not in result.cited_finding_ids
    assert "does/not/exist.yaml" not in result.cited_files
    assert result.hallucination_guard_triggered is True
    assert any(s.get("status") == "hallucination_guard" for s in result.trace)


async def test_insufficient_evidence_path(ctx) -> None:
    db, settings, scan_id, _ = ctx
    final = {"answer": "I think everything is fine (ungrounded).", "cited_finding_ids": []}
    # call_tool=False -> agent finalizes immediately, zero tool calls, no evidence.
    provider = _Provider(str(scan_id), final, call_tool=False)
    async with db.sessionmaker() as session:
        engine = await InvestigationEngine.build(
            session, settings, scan_id=scan_id, provider=provider
        )
        result = await engine.investigate("is everything fine?")
    assert result.tool_calls == 0
    assert result.answer == INSUFFICIENT_EVIDENCE_MESSAGE
    assert result.confidence == "low"
