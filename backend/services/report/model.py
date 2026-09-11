"""The stable, machine-readable report model.

This model is the single source of truth for every export format. Its shape is
versioned via ``schema_version`` so downstream consumers can rely on it. Field
order is meaningful (Pydantic preserves declaration order on dump), which keeps
the JSON output deterministic and diff-friendly.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# Bump only on breaking changes to the JSON structure.
REPORT_SCHEMA_VERSION = "1.0"


class ReportFinding(BaseModel):
    """A single finding as presented in the report, with its full evidence trail."""

    id: str
    rule_id: str
    scanner: str
    category: str
    severity: str
    confidence: str
    title: str
    description: str
    file: str | None = None
    line: int | None = None
    evidence: str | None = None
    recommendation: str


class SeverityBucket(BaseModel):
    """All findings at one severity level (Critical/High/Medium/Low/Info)."""

    severity: str
    label: str
    count: int
    findings: list[ReportFinding] = Field(default_factory=list)


class DomainSection(BaseModel):
    """Findings for one technology/domain view (Docker, Kubernetes, Security...)."""

    key: str
    label: str
    count: int
    findings: list[ReportFinding] = Field(default_factory=list)


class CrossFileRisk(BaseModel):
    """A correlated, cross-file root-cause risk (from the correlation agent)."""

    root_cause: str
    category: str
    severity: str
    confidence: str
    affected_files: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    impact: str
    recommendation: str


class RemediationStep(BaseModel):
    """One prioritized, actionable step in the remediation plan."""

    priority: int
    severity: str
    action: str
    affected_rule_ids: list[str] = Field(default_factory=list)
    affected_files: list[str] = Field(default_factory=list)
    finding_count: int


class CategoryScore(BaseModel):
    """A per-category readiness score with its explanation."""

    category: str
    label: str
    score: int
    weight: float
    applicable: bool
    findings: int
    explanation: str


class ReadinessSection(BaseModel):
    """The production-readiness assessment as shown in the report."""

    score: int
    ready: bool
    rating: str
    summary: str
    confidence: str
    category_scores: list[CategoryScore] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    top_risks: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
    explanation: str = ""


class RepositoryInfo(BaseModel):
    """Repository / scan metadata."""

    name: str
    scan_id: str
    source_type: str
    status: str
    created_at: str | None = None
    completed_at: str | None = None
    total_files: int
    file_type_counts: dict[str, int] = Field(default_factory=dict)
    technologies: list[str] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list)


class ReportModel(BaseModel):
    """The complete audit report, rendered identically to JSON, HTML and PDF."""

    schema_version: str = REPORT_SCHEMA_VERSION
    report_id: str
    generated_at: str
    title: str

    repository: RepositoryInfo
    executive_summary: str
    llm_used: bool

    production_readiness: ReadinessSection

    total_findings: int
    reviewed_false_positives: int
    severity_summary: dict[str, int] = Field(default_factory=dict)

    issues_by_severity: list[SeverityBucket] = Field(default_factory=list)
    findings_by_domain: list[DomainSection] = Field(default_factory=list)
    cross_file_risks: list[CrossFileRisk] = Field(default_factory=list)
    remediation_plan: list[RemediationStep] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    detailed_findings: list[ReportFinding] = Field(default_factory=list)
