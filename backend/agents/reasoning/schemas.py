"""Structured Pydantic outputs for the AI reasoning layer.

Every AI-produced technical finding must be traceable to concrete evidence: a
file, an optional line, the evidence text, and the source (a deterministic
scanner result or a source snippet). Schemas enforce these fields so the model
(or the deterministic fallback) cannot emit an unsupported claim.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from models.enums import Confidence, FindingCategory, Severity


class AIFinding(BaseModel):
    """An AI-reasoned finding. Always backed by evidence from the scan state."""

    title: str
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    file: str | None = None
    line: int | None = None
    evidence: str = Field(min_length=1, description="Concrete evidence text.")
    source: str = Field(min_length=1, description="Scanner result id or source snippet ref.")
    reasoning: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)
    # IDs of the deterministic findings this reasoning is grounded in.
    source_finding_ids: list[str] = Field(default_factory=list)


class RepositoryUnderstanding(BaseModel):
    """High-level, metadata-derived understanding of the repository."""

    summary: str
    technologies: list[str] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list)
    risk_areas: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM


class Correlation(BaseModel):
    """A cross-file relationship insight backed by involved findings/files."""

    title: str
    description: str
    severity: Severity
    confidence: Confidence
    involved_files: list[str] = Field(default_factory=list)
    source_finding_ids: list[str] = Field(default_factory=list)
    reasoning: str
    recommendation: str


class FalsePositiveAssessment(BaseModel):
    """A review of whether a specific finding is likely a false positive."""

    finding_id: str
    is_false_positive: bool
    confidence: Confidence
    reasoning: str


class CategoryScore(BaseModel):
    """Per-category readiness score with an explanation of how it was derived."""

    category: str
    score: int = Field(ge=0, le=100)
    weight: float
    applicable: bool
    findings: int
    counts: dict[str, int] = Field(default_factory=dict)
    explanation: str


class ProductionReadiness(BaseModel):
    """Deterministic, explainable production-readiness assessment.

    The overall score is a weighted average of applicable category scores; each
    category score is 100 minus the sum of severity*confidence-weighted penalties
    for its findings. No number is produced by an LLM.
    """

    ready: bool
    score: int = Field(ge=0, le=100)
    summary: str
    confidence: Confidence
    category_scores: list[CategoryScore] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    top_risks: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
    explanation: str = ""


class FindingGroup(BaseModel):
    """A root-cause group that combines related findings across files/stacks.

    Instead of reporting several symptoms separately, the correlation agent
    collapses them into one issue with the supporting evidence trail. Only
    emitted when backed by real member findings/entities (no invention).
    """

    root_cause: str
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    affected_files: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    impact: str
    recommendation: str
    member_finding_ids: list[str] = Field(default_factory=list)


class AuditReport(BaseModel):
    """The final aggregated report produced by the reasoning layer."""

    scan_id: str
    summary: str
    llm_used: bool
    understanding: RepositoryUnderstanding
    severity_counts: dict[str, int]
    total_findings: int
    reviewed_false_positives: int
    key_findings: list[AIFinding] = Field(default_factory=list)
    correlations: list[Correlation] = Field(default_factory=list)
    finding_groups: list[FindingGroup] = Field(default_factory=list)
    production_readiness: ProductionReadiness
    recommendations: list[str] = Field(default_factory=list)
