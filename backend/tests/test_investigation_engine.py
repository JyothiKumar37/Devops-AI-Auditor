"""Tests for the agentic investigation engine (LangGraph ReAct loop).

Uses a scripted fake LLM provider keyed on the system-prompt role so no network
is needed, plus the real tool registry over a seeded scan.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from agents.investigation.engine import MAX_TOOL_CALLS, InvestigationEngine
from agents.reasoning.llm import LLMMessage, LLMProvider, NullLLMProvider
from core.config import Settings
from core.database import Database
from models.enums import Confidence, FindingCategory, Severity
from models.finding import Finding
from models.scan import RepositoryFile, Scan


class ScriptedProvider(LLMProvider):
    """Fake provider that answers based on the agent role in the system prompt."""

    name = "scripted"

    def __init__(self, scan_id: str, finding_id: str, *, tool_decisions: int = 1) -> None:
        self._scan_id = scan_id
        self._finding_id = finding_id
        self._tool_decisions = tool_decisions
        self._decisions_made = 0

    @property
    def available(self) -> bool:
        return True

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        system = messages[0].content
        if "investigation planner" in system:
            return json.dumps({"intent": "find the biggest risks", "plan": ["list findings"]})
        if "investigation agent" in system:
            if self._decisions_made < self._tool_decisions:
                self._decisions_made += 1
                return json.dumps(
                    {
                        "action": "call_tool",
                        "tool": "get_findings",
                        "tool_args": {"scan_id": self._scan_id, "limit": 5},
                        "purpose": "list findings",
                    }
                )
            return json.dumps({"action": "final"})
        # reporter
        return json.dumps(
            {
                "answer": "Grounded answer about the scan.",
                "root_cause": "example root cause",
                "impact": "example impact",
                "recommendations": ["fix the high finding"],
                "cited_finding_ids": [self._finding_id],
                "cited_files": ["app/config.py"],
            }
        )


class AlwaysToolProvider(ScriptedProvider):
    """Agent always asks to call a tool, to exercise the budget bound."""

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        system = messages[0].content
        if "investigation agent" in system:
            return json.dumps(
                {
                    "action": "call_tool",
                    "tool": "get_findings",
                    "tool_args": {"scan_id": self._scan_id, "limit": 5},
                    "purpose": "loop",
                }
            )
        return super().complete(messages, temperature=temperature)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'eng.db'}",
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
    finding_id = uuid.uuid4()
    async with db.sessionmaker() as session:
        session.add(
            Scan(id=scan_id, repository_name="acme/web", source_type="zip", status="completed")
        )
        session.add(
            RepositoryFile(
                id=file_id, scan_id=scan_id, path="app/config.py", file_type="other",
                size=10, checksum="x" * 64, content="line1\nline2\n",
            )
        )
        session.add(
            Finding(
                id=finding_id, scan_id=scan_id, file_id=file_id,
                category=FindingCategory.SECURITY, severity=Severity.HIGH,
                confidence=Confidence.HIGH, title="Risky thing", description="d",
                evidence="e", recommendation="fix", line_number=1,
                rule_id="RULE1", scanner="config-rules",
            )
        )
        await session.commit()
    yield db, settings, scan_id, finding_id
    await db.dispose()


async def test_investigation_runs_tool_then_answers(ctx) -> None:
    db, settings, scan_id, finding_id = ctx
    provider = ScriptedProvider(str(scan_id), str(finding_id), tool_decisions=1)
    async with db.sessionmaker() as session:
        engine = await InvestigationEngine.build(
            session, settings, scan_id=scan_id, provider=provider
        )
        result = await engine.investigate("What are the biggest risks?")

    assert result.ai_used is True
    assert result.tool_calls == 1
    assert "Grounded answer" in result.answer
    assert str(finding_id) in result.cited_finding_ids
    # Evidence was actually gathered via the tool.
    assert any(e["tool"] == "get_findings" for e in result.evidence)
    # The finding id the agent cited was genuinely retrieved.
    assert str(finding_id) in result.cited_finding_ids
    # Trace is high-level (tool + answer steps), no raw reasoning tokens.
    kinds = {s["kind"] for s in result.trace}
    assert "tool" in kinds and "answer" in kinds


async def test_tool_call_budget_is_bounded(ctx) -> None:
    db, settings, scan_id, finding_id = ctx
    provider = AlwaysToolProvider(str(scan_id), str(finding_id))
    async with db.sessionmaker() as session:
        engine = await InvestigationEngine.build(
            session, settings, scan_id=scan_id, provider=provider
        )
        result = await engine.investigate("loop forever?")
    # The loop is capped by the hard budget regardless of the model's insistence.
    assert result.tool_calls == MAX_TOOL_CALLS
    assert result.answer  # still synthesized a final answer


async def test_falls_back_when_ai_disabled(ctx) -> None:
    db, settings, scan_id, _ = ctx
    async with db.sessionmaker() as session:
        engine = await InvestigationEngine.build(
            session, settings, scan_id=scan_id, provider=NullLLMProvider()
        )
        result = await engine.investigate("why is the score low?")
    assert result.ai_used is False
    assert result.tool_calls == 0
    assert "unavailable" in result.answer.lower()


async def test_unknown_tool_choice_is_ignored(ctx) -> None:
    db, settings, scan_id, finding_id = ctx

    class RogueProvider(ScriptedProvider):
        def complete(self, messages, *, temperature: float = 0.0):  # type: ignore[override]
            system = messages[0].content
            if "investigation agent" in system:
                return json.dumps({"action": "call_tool", "tool": "execute_sql", "tool_args": {}})
            return super().complete(messages, temperature=temperature)

    provider = RogueProvider(str(scan_id), str(finding_id))
    async with db.sessionmaker() as session:
        engine = await InvestigationEngine.build(
            session, settings, scan_id=scan_id, provider=provider
        )
        result = await engine.investigate("try something sneaky")
    # The rogue tool was never executed; engine still produced a safe answer.
    assert result.tool_calls == 0
    assert any(s["kind"] == "note" for s in result.trace)
