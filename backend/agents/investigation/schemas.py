"""Structured schemas for the agentic investigation engine.

Two LLM-facing Pydantic schemas drive the ReAct loop:
- :class:`AgentDecision` - the model's choice each step: call a tool, or finish.
- :class:`FinalAnswer`   - the synthesized, evidence-cited conclusion.

The engine returns a plain :class:`InvestigationResult` dataclass to callers. The
model's private justification is never surfaced; only tool actions, observations,
and the user-facing answer are exposed (no chain-of-thought).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, Field


class AgentDecision(BaseModel):
    """One ReAct step chosen by the model."""

    action: Literal["call_tool", "final"] = "final"
    # When action == call_tool:
    tool: str = ""
    tool_args: dict[str, Any] = Field(default_factory=dict)
    # Short, safe label of WHY this tool (shown in the trace; not chain-of-thought).
    purpose: str = ""


class FinalAnswer(BaseModel):
    """The synthesized conclusion, grounded in gathered evidence."""

    answer: str = ""
    root_cause: str = ""
    impact: str = ""
    recommendations: list[str] = Field(default_factory=list)
    cited_finding_ids: list[str] = Field(default_factory=list)
    cited_files: list[str] = Field(default_factory=list)


@dataclass(slots=True)
class TraceStep:
    """A safe, high-level record of one investigation action (no reasoning tokens)."""

    kind: str  # "plan" | "tool" | "observation" | "answer" | "note"
    label: str
    tool: str | None = None
    status: str | None = None  # "ok" | "error" | code
    returned: int | None = None
    truncated: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind, "label": self.label}
        if self.tool is not None:
            out["tool"] = self.tool
        if self.status is not None:
            out["status"] = self.status
        if self.returned is not None:
            out["returned"] = self.returned
        if self.truncated is not None:
            out["truncated"] = self.truncated
        return out


@dataclass(slots=True)
class EvidenceItem:
    """A piece of evidence the agent actually retrieved via a tool."""

    tool: str
    args: dict[str, Any]
    data: Any
    returned: int = 0
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "args": self.args,
            "returned": self.returned,
            "truncated": self.truncated,
            "data": self.data,
        }


@dataclass(slots=True)
class AIReviewItem:
    """A non-authoritative AI review observation (PR or security review).

    These are explicitly ``source="AI_REVIEW"`` and ``authoritative=False`` - they
    never become deterministic findings, never fail CI/policy/gates.
    """

    title: str
    concern: str
    category: str = "security"
    confidence: str = "low"
    files: list[str] = field(default_factory=list)
    source: str = "AI_REVIEW"
    authoritative: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "concern": self.concern,
            "category": self.category,
            "confidence": self.confidence,
            "files": self.files,
            "source": self.source,
            "authoritative": self.authoritative,
        }


@dataclass(slots=True)
class RemediationStep:
    """One ordered step in a remediation plan, tied to a real finding."""

    order: int
    action: str
    finding_id: str
    rule_id: str
    file: str | None = None
    deterministic_recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "order": self.order,
            "action": self.action,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "file": self.file,
            "deterministic_recommendation": self.deterministic_recommendation,
        }


@dataclass(slots=True)
class RemediationPlan:
    """A proposed, estimate-labeled remediation plan. Never applied without approval."""

    scan_id: str
    problem: str
    root_cause: str
    steps: list[RemediationStep] = field(default_factory=list)
    affected_files: list[str] = field(default_factory=list)
    expected_findings_resolved: list[str] = field(default_factory=list)
    estimated_score_before: int = 0
    estimated_score_after: int = 0
    estimated_score_delta: int = 0
    estimate_note: str = (
        "Score impact is a deterministic ESTIMATE assuming the targeted findings are "
        "fully resolved and no new issues are introduced; re-scan to confirm."
    )
    risk_level: str = "low"
    requires_approval: bool = True
    status: str = "proposed"
    label: str = "AI Remediation Plan"
    ai_used: bool = False
    confidence: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "problem": self.problem,
            "root_cause": self.root_cause,
            "steps": [s.to_dict() for s in self.steps],
            "affected_files": self.affected_files,
            "expected_findings_resolved": self.expected_findings_resolved,
            "estimated_score_before": self.estimated_score_before,
            "estimated_score_after": self.estimated_score_after,
            "estimated_score_delta": self.estimated_score_delta,
            "estimate_note": self.estimate_note,
            "risk_level": self.risk_level,
            "requires_approval": self.requires_approval,
            "status": self.status,
            "label": self.label,
            "ai_used": self.ai_used,
            "confidence": self.confidence,
        }


@dataclass(slots=True)
class InvestigationResult:
    """The engine's final output for one investigation."""

    question: str
    answer: str
    root_cause: str = ""
    impact: str = ""
    recommendations: list[str] = field(default_factory=list)
    confidence: str = "low"  # high | medium | low (deterministic, evidence-based)
    cited_finding_ids: list[str] = field(default_factory=list)
    cited_files: list[str] = field(default_factory=list)
    citations: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    # Every result from this engine is AI analysis, never a deterministic finding.
    label: str = "AI Insight"
    ai_used: bool = False
    tool_calls: int = 0
    hallucination_guard_triggered: bool = False
    investigation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "question": self.question,
            "answer": self.answer,
            "root_cause": self.root_cause,
            "impact": self.impact,
            "recommendations": self.recommendations,
            "confidence": self.confidence,
            "cited_finding_ids": self.cited_finding_ids,
            "cited_files": self.cited_files,
            "citations": self.citations,
            "evidence": self.evidence,
            "trace": self.trace,
            "label": self.label,
            "ai_used": self.ai_used,
            "tool_calls": self.tool_calls,
            "hallucination_guard_triggered": self.hallucination_guard_triggered,
        }
