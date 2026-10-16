"""M5 tests: AI incident investigation (tools, scope, grounding, safeguards).

Deterministic fallback (AI off) plus a scripted provider to exercise the full
tool-grounded path, citation grounding, the hallucination guard, and incident/
account scope enforcement.
"""

from __future__ import annotations

import json
import uuid

import pytest

from agents.investigation.engine import InvestigationEngine
from agents.investigation.tools.base import ToolError
from agents.investigation.tools.registry import incident_registry
from agents.reasoning.llm import LLMMessage, LLMProvider
from models.cloud import CloudAccount
from models.security import SecurityEvent
from services.incident_service import IncidentService
from services.investigation_service import InvestigationService

FINDING_ID = str(uuid.uuid4())


def _event(**kw) -> SecurityEvent:
    base = dict(
        id=uuid.uuid4(), source_type="guardduty", source_event_id=str(uuid.uuid4()),
        category="threat", event_type="Recon", severity="high", confidence="medium",
        title="event", fingerprint=uuid.uuid4().hex, status="new",
    )
    base.update(kw)
    return SecurityEvent(**base)


class ScriptedProvider(LLMProvider):
    name = "scripted"

    def __init__(self, incident_id: str, *, cite: list[str], tool: str = "search_security_events"):
        self._incident_id = incident_id
        self._cite = cite
        self._tool = tool
        self._called = False

    @property
    def available(self) -> bool:
        return True

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        system = messages[0].content
        if "investigation planner" in system:
            return json.dumps({"intent": "assess the incident", "plan": ["gather events"]})
        if "investigation agent" in system:
            if not self._called:
                self._called = True
                return json.dumps({
                    "action": "call_tool", "tool": self._tool,
                    "tool_args": {"incident_id": self._incident_id}, "purpose": "gather",
                })
            return json.dumps({"action": "final"})
        return json.dumps({
            "answer": "The incident stems from a public resource.",
            "root_cause": "misconfig", "impact": "exposure",
            "recommendations": ["restrict access"],
            "cited_finding_ids": self._cite, "cited_files": [],
        })


async def _account(sm) -> uuid.UUID:
    pk = uuid.uuid4()
    async with sm() as session:
        session.add(CloudAccount(
            id=pk, provider="aws", name="prod", account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/RO", regions=["us-east-1"],
            status="connected",
        ))
        await session.commit()
    return pk


async def _incident(sm, settings, account_id=None) -> uuid.UUID:
    async with sm() as session:
        session.add(_event(
            cloud_account_id=account_id, account_ref="123456789012", resource_id="i-1",
            title="Public EC2", severity="high", verified=True,
            related_finding_ids=[FINDING_ID],
        ))
        session.add(_event(
            cloud_account_id=account_id, account_ref="123456789012", resource_id="i-1",
            title="GuardDuty brute force", severity="critical",
        ))
        await session.commit()
        incidents = await IncidentService(session, settings).correlate_new_events()
        await session.commit()
        return incidents[0].id


async def test_incident_investigation_fallback(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _incident(sm, settings)
    async with sm() as session:
        result = await InvestigationService(session, settings).investigate_incident(
            inc_id, "What happened?"
        )
        await session.commit()
        assert result.ai_used is False
        assert result.label == "AI Insight"
        # Persisted.
        rows = await InvestigationService(session, settings).list_incident_investigations(inc_id)
        assert len(rows) == 1


async def test_incident_investigation_grounded_with_provider(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _incident(sm, settings)
    provider = ScriptedProvider(str(inc_id), cite=[FINDING_ID])
    async with sm() as session:
        engine = await InvestigationEngine.build(
            session, settings, incident_id=inc_id, registry=incident_registry(),
            provider=provider,
        )
        result = await engine.investigate("Investigate this incident.")
        assert result.ai_used is True
        assert result.tool_calls == 1
        assert any(e["tool"] == "search_security_events" for e in result.evidence)
        # The cited finding id was genuinely retrieved (via related_finding_ids).
        assert FINDING_ID in result.cited_finding_ids
        assert result.hallucination_guard_triggered is False


async def test_hallucination_guard_drops_uncited(mem_db) -> None:
    sm, settings = mem_db
    inc_id = await _incident(sm, settings)
    bogus = str(uuid.uuid4())
    provider = ScriptedProvider(str(inc_id), cite=[bogus])
    async with sm() as session:
        engine = await InvestigationEngine.build(
            session, settings, incident_id=inc_id, registry=incident_registry(),
            provider=provider,
        )
        result = await engine.investigate("Investigate this incident.")
        assert bogus not in result.cited_finding_ids
        assert result.hallucination_guard_triggered is True


async def test_incident_scope_enforced(mem_db) -> None:
    sm, settings = mem_db
    inc_a = await _incident(sm, settings)
    other = uuid.uuid4()
    async with sm() as session:
        engine = await InvestigationEngine.build(
            session, settings, incident_id=inc_a, registry=incident_registry(),
        )
        # Accessing a different incident is rejected as unauthorized.
        with pytest.raises(ToolError) as exc:
            await engine._registry.call(  # noqa: SLF001 - testing scope guard
                "get_incident", engine._ctx, {"incident_id": str(other)}
            )
        assert exc.value.code == "unauthorized"


async def test_cloud_account_scope_enforced_in_incident(mem_db) -> None:
    sm, settings = mem_db
    acct = await _account(sm)
    inc_id = await _incident(sm, settings, account_id=acct)
    other_account = uuid.uuid4()
    async with sm() as session:
        engine = await InvestigationEngine.build(
            session, settings, incident_id=inc_id, account_id=acct,
            registry=incident_registry(),
        )
        with pytest.raises(ToolError) as exc:
            await engine._registry.call(  # noqa: SLF001
                "get_cloud_findings", engine._ctx, {"account_id": str(other_account)}
            )
        assert exc.value.code == "unauthorized"
