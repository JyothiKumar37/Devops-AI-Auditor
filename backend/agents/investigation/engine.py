"""Agentic investigation engine (LangGraph).

A bounded, evidence-grounded ReAct workflow:

    understand_intent -> agent_decide -> (call_tool -> execute_tool -> agent_decide)*
                                      -> synthesize -> END

The model may only gather evidence through the controlled, read-only tool
registry (never raw DB/shell/code). The loop is bounded by a hard tool-call
budget so an investigation cannot run away in cost or time. When no LLM provider
is configured, the engine falls back to a deterministic, tool-only summary so the
feature degrades gracefully instead of failing.

The deterministic scanner/policy engine remains authoritative; this engine only
explains, correlates and recommends on top of it.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from functools import partial
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field

from agents.investigation.schemas import (
    AgentDecision,
    EvidenceItem,
    FinalAnswer,
    InvestigationResult,
    TraceStep,
)
from agents.investigation.tools import ToolContext, ToolError, ToolPermission
from agents.investigation.tools.registry import ToolRegistry, default_registry
from agents.investigation.verification import (
    INSUFFICIENT_EVIDENCE_MESSAGE,
    build_citations,
    compute_confidence,
    verify_citations,
)
from agents.reasoning.llm import LLMProvider, generate_structured, get_provider
from agents.reasoning.sanitize import guardrail_system, wrap_untrusted
from core.config import Settings
from core.logging import get_logger
from services.runtime_config import resolve_settings

logger = get_logger(__name__)

# Hard bounds (cost/latency/safety). Cross-checked by both the graph router and
# the engine so a misbehaving model cannot loop indefinitely.
MAX_TOOL_CALLS = 8
MAX_EVIDENCE_CHARS = 7000
RECURSION_LIMIT = 40


class _IntentPlan(BaseModel):
    """Intent + short plan produced by the understand-intent node."""

    intent: str = ""
    plan: list[str] = Field(default_factory=list)


class InvestigationState(TypedDict, total=False):
    question: str
    intent: str
    plan: list[str]
    evidence: list[dict[str, Any]]
    trace: list[dict[str, Any]]
    seen_finding_ids: list[str]
    seen_files: list[str]
    tool_calls: int
    pending: dict[str, Any] | None
    final: dict[str, Any] | None
    ai_used: bool


class InvestigationEngine:
    """Runs one investigation to completion, returning an InvestigationResult."""

    def __init__(
        self,
        settings: Settings,
        provider: LLMProvider,
        registry: ToolRegistry,
        ctx: ToolContext,
    ) -> None:
        self._settings = settings
        self._provider = provider
        self._registry = registry
        self._ctx = ctx
        self._tool_specs = registry.specs(ctx.granted_permissions)

    @classmethod
    async def build(
        cls,
        session: Any,
        settings: Settings,
        *,
        scan_id: uuid.UUID | None = None,
        repository_name: str | None = None,
        registry: ToolRegistry | None = None,
        provider: LLMProvider | None = None,
    ) -> InvestigationEngine:
        """Construct an engine with runtime model override + READ-only scope."""
        resolved = await resolve_settings(session, settings)
        prov = provider if provider is not None else get_provider(resolved)
        ctx = ToolContext(
            session=session,
            settings=resolved,
            authorized_scan_ids=frozenset({scan_id}) if scan_id else None,
            granted_permissions=frozenset({ToolPermission.READ}),
            repository_name=repository_name,
        )
        return cls(resolved, prov, registry or default_registry(), ctx)

    # ---- public API --------------------------------------------------------

    async def investigate(self, question: str) -> InvestigationResult:
        graph = self._build_graph()
        initial: InvestigationState = {
            "question": question.strip(),
            "evidence": [],
            "trace": [],
            "seen_finding_ids": [],
            "seen_files": [],
            "tool_calls": 0,
            "pending": None,
            "final": None,
            "ai_used": self._provider.available,
        }
        final_state: InvestigationState = await graph.ainvoke(
            initial, config={"recursion_limit": RECURSION_LIMIT}
        )
        return self._to_result(final_state)

    # ---- graph construction ------------------------------------------------

    def _build_graph(self):  # type: ignore[no-untyped-def]
        graph: StateGraph = StateGraph(InvestigationState)
        graph.add_node("understand_intent", partial(self._understand_intent))
        graph.add_node("agent_decide", partial(self._agent_decide))
        graph.add_node("execute_tool", partial(self._execute_tool))
        graph.add_node("synthesize", partial(self._synthesize))
        graph.add_edge(START, "understand_intent")
        graph.add_edge("understand_intent", "agent_decide")
        graph.add_conditional_edges(
            "agent_decide", self._route, {"tool": "execute_tool", "final": "synthesize"}
        )
        graph.add_edge("execute_tool", "agent_decide")
        graph.add_edge("synthesize", END)
        return graph.compile()

    # ---- nodes -------------------------------------------------------------

    async def _understand_intent(self, state: InvestigationState) -> dict[str, Any]:
        question = state["question"]
        intent, plan = question, []
        if self._provider.available:
            schema = _IntentPlan
            system = guardrail_system("the investigation planner")
            user = (
                "Restate the user's question as a one-line intent and a short, "
                "ordered plan (max 5 steps) of what evidence to gather using the "
                "available tools. Respond ONLY as JSON "
                '{"intent": str, "plan": [str, ...]}.\n\n'
                f"Available tools: {[s['name'] for s in self._tool_specs]}\n\n"
                + wrap_untrusted(question)
            )
            result = await asyncio.to_thread(
                generate_structured, self._provider, system=system, user=user, schema=schema
            )
            if result is not None:
                intent = result.intent.strip() or question
                plan = [p.strip() for p in result.plan[:5] if p.strip()]
        trace = [TraceStep(kind="plan", label=intent).to_dict()]
        for step in plan:
            trace.append(TraceStep(kind="plan", label=step).to_dict())
        return {"intent": intent, "plan": plan, "trace": state["trace"] + trace}

    async def _agent_decide(self, state: InvestigationState) -> dict[str, Any]:
        # Budget guard: once exhausted, stop gathering and synthesize.
        if state["tool_calls"] >= MAX_TOOL_CALLS or not self._provider.available:
            return {"pending": None}

        system = self._agent_system()
        user = self._agent_user(state)
        decision = await asyncio.to_thread(
            generate_structured,
            self._provider,
            system=system,
            user=user,
            schema=AgentDecision,
        )
        if decision is None or decision.action == "final":
            return {"pending": None}
        if decision.tool not in {s["name"] for s in self._tool_specs}:
            # Model picked an unknown/unauthorized tool: record and stop gathering.
            note = TraceStep(
                kind="note", label=f"Ignored unavailable tool '{decision.tool}'."
            ).to_dict()
            return {"pending": None, "trace": state["trace"] + [note]}
        return {"pending": decision.model_dump()}

    def _route(self, state: InvestigationState) -> str:
        return "tool" if state.get("pending") else "final"

    async def _execute_tool(self, state: InvestigationState) -> dict[str, Any]:
        pending = state["pending"] or {}
        tool_name = pending.get("tool", "")
        args = pending.get("tool_args") or {}
        purpose = pending.get("purpose") or ""
        trace = list(state["trace"])
        evidence = list(state["evidence"])
        seen_findings = set(state["seen_finding_ids"])
        seen_files = set(state["seen_files"])

        try:
            result = await self._registry.call(tool_name, self._ctx, args)
        except ToolError as exc:
            trace.append(
                TraceStep(
                    kind="observation", label=f"{tool_name}: {exc.message[:120]}",
                    tool=tool_name, status=exc.code,
                ).to_dict()
            )
            return {
                "pending": None,
                "trace": trace,
                "tool_calls": state["tool_calls"] + 1,
            }

        item = EvidenceItem(
            tool=tool_name, args=args, data=result.data,
            returned=result.returned, truncated=result.truncated,
        )
        evidence.append(item.to_dict())
        _collect_refs(result.data, seen_findings, seen_files)
        label = purpose or f"Called {tool_name}"
        trace.append(
            TraceStep(
                kind="tool", label=label, tool=tool_name, status="ok",
                returned=result.returned, truncated=result.truncated,
            ).to_dict()
        )
        return {
            "pending": None,
            "evidence": evidence,
            "trace": trace,
            "seen_finding_ids": sorted(seen_findings),
            "seen_files": sorted(seen_files),
            "tool_calls": state["tool_calls"] + 1,
        }

    async def _synthesize(self, state: InvestigationState) -> dict[str, Any]:
        trace = state["trace"] + [
            TraceStep(kind="answer", label="Synthesized conclusion from evidence.").to_dict()
        ]
        if not self._provider.available:
            return {"final": self._deterministic_answer(state), "trace": trace}

        system = self._synthesize_system()
        user = self._synthesize_user(state)
        answer = await asyncio.to_thread(
            generate_structured,
            self._provider,
            system=system,
            user=user,
            schema=FinalAnswer,
        )
        if answer is None:
            return {"final": self._deterministic_answer(state), "trace": trace}
        return {"final": answer.model_dump(), "trace": trace}

    # ---- prompt builders ---------------------------------------------------

    def _agent_system(self) -> str:
        base = guardrail_system("the DevOps investigation agent")
        return (
            base
            + "\nYou investigate by calling ONE read-only tool at a time to gather "
            "evidence, then stop. Rules:\n"
            "- Only use tools from the provided list; pass arguments exactly as the "
            "tool requires.\n"
            "- Gather only the evidence you need to answer the question. Do not call "
            "the same tool with the same arguments twice.\n"
            "- When you have enough evidence, choose action 'final'.\n"
            "- The deterministic scores and findings are authoritative; never "
            "contradict or recompute them.\n"
            'Respond ONLY as JSON {"action": "call_tool"|"final", "tool": str, '
            '"tool_args": object, "purpose": str}.'
        )

    def _agent_user(self, state: InvestigationState) -> str:
        remaining = MAX_TOOL_CALLS - state["tool_calls"]
        tools_desc = json.dumps(self._tool_specs, indent=0)[:3000]
        return (
            f"Question: {state['question']}\n"
            f"Intent: {state.get('intent', '')}\n"
            f"Scan scope: {self._scope_hint()}\n"
            f"Tool-call budget remaining: {remaining}\n\n"
            f"Available tools (name/description/arguments):\n{tools_desc}\n\n"
            "Evidence gathered so far:\n"
            + wrap_untrusted(self._render_evidence(state))
            + "\n\nChoose the next action."
        )

    def _synthesize_system(self) -> str:
        base = guardrail_system("the DevOps investigation reporter")
        return (
            base
            + "\nWrite the final answer grounded ONLY in the gathered evidence. "
            "Rules:\n"
            "- Cite the finding ids and file paths you actually used (they must "
            "appear in the evidence).\n"
            "- If the evidence is insufficient, say so plainly in 'answer' rather "
            "than guessing.\n"
            "- Never invent findings, files, line numbers, scores, or history.\n"
            "- Deterministic findings/scores are authoritative; your output is "
            "explanatory analysis and recommendations.\n"
            'Respond ONLY as JSON {"answer": str, "root_cause": str, "impact": str, '
            '"recommendations": [str], "cited_finding_ids": [str], "cited_files": [str]}.'
        )

    def _synthesize_user(self, state: InvestigationState) -> str:
        return (
            f"Question: {state['question']}\n\n"
            "Evidence (the only facts you may use):\n"
            + wrap_untrusted(self._render_evidence(state))
            + "\n\nWrite the grounded final answer as JSON."
        )

    # ---- helpers -----------------------------------------------------------

    def _scope_hint(self) -> str:
        if self._ctx.authorized_scan_ids:
            return f"scan(s) {sorted(str(s) for s in self._ctx.authorized_scan_ids)}"
        if self._ctx.repository_name:
            return f"repository {self._ctx.repository_name}"
        return "unrestricted"

    def _render_evidence(self, state: InvestigationState) -> str:
        if not state["evidence"]:
            return "(no evidence gathered yet)"
        rendered = json.dumps(state["evidence"], default=str)
        if len(rendered) > MAX_EVIDENCE_CHARS:
            rendered = rendered[:MAX_EVIDENCE_CHARS] + "...[evidence truncated]"
        return rendered

    def _deterministic_answer(self, state: InvestigationState) -> dict[str, Any]:
        """A tool-only fallback answer when the LLM is unavailable/failed."""
        n = len(state["evidence"])
        if n == 0:
            return {
                "answer": (
                    "AI investigation is unavailable (no LLM provider configured). "
                    "The deterministic scan data remains available via the dashboard "
                    "and API."
                ),
                "root_cause": "",
                "impact": "",
                "recommendations": [],
                "cited_finding_ids": [],
                "cited_files": [],
            }
        return {
            "answer": (
                "AI synthesis is unavailable, so here is the raw deterministic "
                f"evidence gathered from {n} tool call(s). Review the evidence and "
                "posture scores directly."
            ),
            "root_cause": "",
            "impact": "",
            "recommendations": [],
            "cited_finding_ids": state["seen_finding_ids"],
            "cited_files": state["seen_files"],
        }

    def _to_result(self, state: InvestigationState) -> InvestigationResult:
        final = state.get("final") or {}
        ai_used = bool(state.get("ai_used"))
        tool_calls = state.get("tool_calls", 0)
        trace = list(state.get("trace", []))

        # Hallucination guard: keep only citations the agent actually retrieved.
        check = verify_citations(
            list(final.get("cited_finding_ids", [])),
            list(final.get("cited_files", [])),
            set(state.get("seen_finding_ids", [])),
            set(state.get("seen_files", [])),
        )
        if check.had_hallucination:
            trace.append(
                TraceStep(
                    kind="note",
                    label=(
                        "Dropped unverifiable citations "
                        f"(findings={len(check.dropped_finding_ids)}, "
                        f"files={len(check.dropped_files)})."
                    ),
                    status="hallucination_guard",
                ).to_dict()
            )

        confidence = compute_confidence(check, tool_calls=tool_calls, ai_used=ai_used)
        answer = final.get("answer", "")

        # Insufficient-evidence path: AI answered repo-fact questions with nothing
        # verifiable to stand on -> replace with an explicit uncertainty message.
        if ai_used and not check.has_verified_evidence and tool_calls == 0:
            answer = INSUFFICIENT_EVIDENCE_MESSAGE
            confidence = "low"

        return InvestigationResult(
            question=state["question"],
            answer=answer,
            root_cause=final.get("root_cause", ""),
            impact=final.get("impact", ""),
            recommendations=list(final.get("recommendations", [])),
            confidence=confidence,
            cited_finding_ids=check.verified_finding_ids,
            cited_files=check.verified_files,
            citations=build_citations(check),
            evidence=state.get("evidence", []),
            trace=trace,
            ai_used=ai_used,
            tool_calls=tool_calls,
            hallucination_guard_triggered=check.had_hallucination,
        )


def _collect_refs(data: Any, finding_ids: set[str], files: set[str]) -> None:
    """Recursively collect finding_id and file/path values actually returned.

    These feed the M3 citation verifier - the agent may only cite references it
    genuinely retrieved.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "finding_id" and isinstance(value, str):
                finding_ids.add(value)
            elif key in {"file", "path"} and isinstance(value, str) and value:
                files.add(value)
            else:
                _collect_refs(value, finding_ids, files)
    elif isinstance(data, list):
        for item in data:
            _collect_refs(item, finding_ids, files)
