"""Shared Pydantic schemas used by the API layer."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class HealthState(str, Enum):
    """Overall or per-component health state."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class ComponentHealth(BaseModel):
    """Health of a single downstream dependency."""

    name: str
    state: HealthState
    detail: str | None = None


class HealthResponse(BaseModel):
    """Response body for the readiness health endpoint."""

    status: HealthState
    version: str
    environment: str
    components: list[ComponentHealth] = Field(default_factory=list)


class LivenessResponse(BaseModel):
    """Response body for the liveness endpoint."""

    status: str = "ok"


class LLMHealthResponse(BaseModel):
    """Result of an on-demand LLM connectivity check."""

    provider: str
    model: str
    configured: bool
    ok: bool
    detail: str
    latency_ms: int | None = None


class LLMSettingsResponse(BaseModel):
    """Current effective LLM configuration and any runtime override."""

    provider: str
    model: str  # effective model (override if set, else the env default)
    env_model: str  # the environment default
    overridden: bool
    configured: bool


class LLMModelUpdate(BaseModel):
    """Set (or clear, when empty) the runtime LLM model override."""

    model: str = Field(default="", max_length=128)


# ---- AI assistance (interactive LLM features) -----------------------------


class AiExplanation(BaseModel):
    explanation: str


class AiFixSuggestion(BaseModel):
    """A review-only AI-proposed patch. Never auto-applied."""

    file_path: str | None = None
    before: str
    after: str
    diff: str
    explanation: str
    changed: bool


class AiTriage(BaseModel):
    likely_false_positive: bool
    confidence: str
    reason: str


class AiScanSummary(BaseModel):
    summary: str


class AiPriorityItem(BaseModel):
    finding_id: uuid.UUID
    rule_id: str
    severity: str
    title: str
    file: str | None = None
    rationale: str


class AiPriorities(BaseModel):
    items: list[AiPriorityItem] = []


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)


class AiAnswer(BaseModel):
    answer: str


class ChatMessageRead(BaseModel):
    """One persisted message in a scan's AI conversation."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    role: str
    content: str
    created_at: datetime


class ChatHistory(BaseModel):
    """A scan's full AI conversation, oldest first."""

    scan_id: uuid.UUID
    messages: list[ChatMessageRead] = []


class ServiceInfo(BaseModel):
    """Basic service metadata returned at the API root."""

    name: str
    version: str
    environment: str
    docs_url: str


# ---------------------------------------------------------------------------
# Scan / ingestion schemas
# ---------------------------------------------------------------------------

import uuid  # noqa: E402
from datetime import datetime  # noqa: E402

from models.enums import ScanStatus, SourceType  # noqa: E402


class ScanSummary(BaseModel):
    """Summary view of a scan, used in list and detail responses."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    repository_name: str
    source_type: SourceType
    status: ScanStatus
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    file_count: int = 0
    readiness: int | None = None


class RepositoryFileRead(BaseModel):
    """A single indexed repository file."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    scan_id: uuid.UUID
    path: str
    file_type: str
    size: int
    checksum: str


class GitScanRequest(BaseModel):
    """Request to ingest a repository directly from a git clone URL."""

    repository_url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="HTTP(S) URL of the git repository to clone and analyse.",
    )
    ref: str | None = Field(
        default=None,
        max_length=255,
        description="Optional branch or tag to clone (defaults to the repo's default branch).",
    )


class ScanListResponse(BaseModel):
    """Paginated list of scans."""

    items: list[ScanSummary]
    total: int


class ScanFilesResponse(BaseModel):
    """The files discovered for a scan."""

    scan_id: uuid.UUID
    total: int
    items: list[RepositoryFileRead]


class ScanDiffFinding(BaseModel):
    """A finding as represented in a scan-to-scan diff (file path resolved)."""

    rule_id: str
    scanner: str
    category: str
    severity: str
    confidence: str
    title: str
    file: str | None = None
    line: int | None = None
    recommendation: str = ""


class ScanDiffSummary(BaseModel):
    """Aggregate counts for a scan-to-scan diff."""

    new: int
    fixed: int
    unchanged: int
    base_total: int
    head_total: int


class ScanDiffResponse(BaseModel):
    """Comparison of a scan (head) against a previous or explicit base scan.

    Findings are matched across scans by a stable fingerprint of
    (rule_id, file path, evidence) - deliberately independent of line numbers so
    that unrelated edits shifting a file's line count do not spuriously report a
    finding as both fixed and new. `base_scan_id` is null when no earlier scan of
    the repository exists, in which case every current finding is reported as new.
    """

    base_scan_id: uuid.UUID | None = None
    head_scan_id: uuid.UUID
    repository_name: str
    base_created_at: datetime | None = None
    head_created_at: datetime
    base_readiness: int | None = None
    head_readiness: int
    readiness_delta: int | None = None
    summary: ScanDiffSummary
    new_severity_counts: dict[str, int] = {}
    fixed_severity_counts: dict[str, int] = {}
    new_findings: list[ScanDiffFinding] = []
    fixed_findings: list[ScanDiffFinding] = []
    unchanged_findings: list[ScanDiffFinding] = []


class DiscoveryResponse(BaseModel):
    """Structured, grouped output of the Repository Discovery Agent.

    `categories` maps each discovery category (docker, compose, kubernetes,
    terraform, cicd, helm, ansible, shell, configuration, other) to the files
    classified into it.
    """

    scan_id: uuid.UUID
    total: int
    counts: dict[str, int]
    categories: dict[str, list[RepositoryFileRead]]


# ---------------------------------------------------------------------------
# Finding schemas
# ---------------------------------------------------------------------------

from models.enums import (  # noqa: E402
    Confidence,
    FindingCategory,
    Severity,
    SuppressionReason,
)


class RiskFactorsRead(BaseModel):
    """The bounded contributions that make up a finding's risk score."""

    severity_base: int
    exploitability: int
    exposure: int
    production_impact: int
    recurrence: int
    confidence_factor: float
    asset_criticality: float


class FindingRead(BaseModel):
    """A single scanner finding, exposing the full evidence trail."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    scan_id: uuid.UUID
    file_id: uuid.UUID | None = None
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    evidence: str | None = None
    line_number: int | None = None
    recommendation: str
    rule_id: str
    scanner: str
    # Baseline/suppression status (annotated at read time, not stored on the row).
    suppressed: bool = False
    suppression_reason: SuppressionReason | None = None
    suppression_note: str | None = None
    # Deterministic risk prioritisation (annotated at read time, never stored).
    # `risk_score` is 0-100; `risk_priority` is immediate|high|normal|low.
    risk_score: int = 0
    risk_priority: str = "low"
    risk_explanation: str = ""
    risk_signals: list[str] = []
    risk_factors: RiskFactorsRead | None = None


class FindingsResponse(BaseModel):
    """A list of findings for a scan, with per-severity counts."""

    scan_id: uuid.UUID
    total: int
    severity_counts: dict[str, int]
    # How many of the scan's findings are currently suppressed (baselined).
    suppressed_count: int = 0
    items: list[FindingRead]


class TrendPoint(BaseModel):
    """One scan's metrics as a point on the repository's timeline."""

    scan_id: uuid.UUID
    created_at: datetime
    status: str
    readiness: int
    total_findings: int
    severity_counts: dict[str, int] = {}
    new_findings: int = 0
    fixed_findings: int = 0
    unchanged_findings: int = 0


class TrendsResponse(BaseModel):
    """Historical trend of a repository's scans, oldest first.

    Points cover the repository's completed scans in chronological order so the
    UI can chart readiness, findings and severity over time. new/fixed/unchanged
    are relative to the immediately preceding completed scan (the first point has
    everything as 'new').
    """

    repository_name: str
    total_scans: int
    points: list[TrendPoint] = []


class RiskSummaryItem(BaseModel):
    """A single finding as ranked by the deterministic risk engine."""

    finding_id: uuid.UUID
    rule_id: str
    scanner: str
    category: str
    severity: str
    confidence: str
    title: str
    file: str | None = None
    line: int | None = None
    risk_score: int
    risk_priority: str
    risk_explanation: str


class IntegrationConnectRequest(BaseModel):
    """Connect an SCM provider with an access token (PAT or App token)."""

    provider: str  # github | gitlab
    token: str
    name: str | None = None


class IntegrationRead(BaseModel):
    """A connected integration. The access token is NEVER included."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    provider: str
    account: str | None = None
    name: str
    status: str
    api_url: str
    created_at: datetime


class IntegrationListResponse(BaseModel):
    total: int
    items: list[IntegrationRead] = []


class RemoteRepository(BaseModel):
    """A repository as listed live from a provider (not yet imported)."""

    external_id: str
    owner: str
    name: str
    full_name: str
    default_branch: str
    web_url: str
    private: bool


class RemoteRepositoryListResponse(BaseModel):
    total: int
    items: list[RemoteRepository] = []


class RepositoryImportRequest(BaseModel):
    owner: str
    name: str


class SCMRepositoryRead(BaseModel):
    """An imported repository tracked for PR scanning."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    integration_id: uuid.UUID
    provider: str
    owner: str
    name: str
    full_name: str
    default_branch: str
    web_url: str
    private: bool
    policy_id: uuid.UUID | None = None
    created_at: datetime


class SCMRepositoryListResponse(BaseModel):
    total: int
    items: list[SCMRepositoryRead] = []


class PolicyCreateRequest(BaseModel):
    name: str
    yaml_text: str
    description: str = ""


class PolicyUpdateRequest(BaseModel):
    yaml_text: str | None = None
    description: str | None = None
    enabled: bool | None = None


class PolicyRead(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    description: str
    yaml_text: str
    version: int
    enabled: bool
    created_at: datetime
    updated_at: datetime


class PolicyListResponse(BaseModel):
    total: int
    items: list[PolicyRead] = []


class PolicyVersionRead(BaseModel):
    model_config = {"from_attributes": True}

    version: int
    yaml_text: str
    created_at: datetime


class PolicyAssignRequest(BaseModel):
    scope_type: str  # repo | global
    scope_value: str = ""
    environment: str | None = None


class PolicyEvaluateRequest(BaseModel):
    """Evaluate a policy against a scan's findings or an inline finding list."""

    scan_id: uuid.UUID | None = None
    findings: list[dict] | None = None
    environment: str | None = None


class PolicyEvaluationResult(BaseModel):
    status: str
    rules: list[dict] = []
    violations: list[dict] = []


class PullRequestScanRead(BaseModel):
    """The deterministic result of one incremental PR scan."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    pull_request_id: uuid.UUID
    head_sha: str
    status: str
    changed_files: int
    new_findings: int
    fixed_findings: int
    pr_risk_score: int
    readiness_before: int
    readiness_after: int
    gate_status: str
    severity_delta: dict[str, int] | None = None
    findings_detail: list[dict] | None = None
    policy_result: dict | None = None
    summary: str = ""
    created_at: datetime


class PullRequestRead(BaseModel):
    """A tracked pull/merge request."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    provider: str
    repo_full_name: str
    number: int
    title: str
    author: str
    base_ref: str
    head_ref: str
    head_sha: str
    web_url: str
    state: str
    created_at: datetime
    updated_at: datetime


class PullRequestListResponse(BaseModel):
    total: int
    items: list[PullRequestRead] = []


class PullRequestDetail(BaseModel):
    """A pull request plus its scan history (most recent first)."""

    pull_request: PullRequestRead
    latest_scan: PullRequestScanRead | None = None
    scans: list[PullRequestScanRead] = []


class DependencyItem(BaseModel):
    """A single resolved dependency in the software bill of materials."""

    name: str
    version: str
    ecosystem: str
    scope: str  # "direct" | "transitive"
    license: str | None = None
    purl: str
    sources: list[str] = []


class DependenciesResponse(BaseModel):
    """Dependency inventory for a scan (parsed from manifests/lockfiles).

    `vulnerabilities_available` is false because no vulnerability database is
    bundled - the severity buckets are therefore always zero and MUST NOT be
    read as "no vulnerabilities". This is an inventory (SBOM), not a vuln scan.
    """

    scan_id: uuid.UUID
    total: int
    direct: int
    transitive: int
    ecosystem_counts: dict[str, int] = {}
    vulnerabilities_available: bool = False
    vulnerability_counts: dict[str, int] = {}
    items: list[DependencyItem] = []


class ContainerCategoryScore(BaseModel):
    """A single container-security dimension's 0-100 score."""

    key: str
    label: str
    score: int
    findings: int
    counts: dict[str, int] = {}
    explanation: str


class ContainerSecurityResponse(BaseModel):
    """Container-security score for a scan (Docker + Compose).

    `applicable` is false when the repository has no Dockerfile/Compose file, in
    which case `overall` is 100. All scores are deterministic (0-100).
    """

    scan_id: uuid.UUID
    applicable: bool
    overall: int
    total_findings: int = 0
    categories: list[ContainerCategoryScore] = []


class K8sCategoryScore(BaseModel):
    """A single Kubernetes readiness dimension's 0-100 score."""

    key: str
    label: str
    score: int
    findings: int
    counts: dict[str, int] = {}
    explanation: str


class KubernetesScoreResponse(BaseModel):
    """Kubernetes production-readiness score for a scan.

    `applicable` is false when the repository has no Kubernetes manifests, in
    which case `overall` is 100 and categories carry no findings. All scores are
    deterministic (0-100); no value comes from an LLM.
    """

    scan_id: uuid.UUID
    applicable: bool
    overall: int
    total_findings: int = 0
    categories: list[K8sCategoryScore] = []


class PostureCategory(BaseModel):
    """A single posture domain's deterministic 0-100 score."""

    key: str
    label: str
    score: int
    applicable: bool
    findings: int
    counts: dict[str, int] = {}
    explanation: str


class AffectedFile(BaseModel):
    """A repository file ranked by how many findings it carries."""

    file: str
    findings: int
    max_severity: str


class PostureResponse(BaseModel):
    """Security/DevOps posture overview for a scan.

    `overall` is the deterministic production-readiness score (single source of
    truth); `categories` are the per-domain scores. New/fixed/unchanged counts
    come from the diff against the previous scan of the same repository (0 when
    there is no prior scan). Active (non-suppressed) findings only.
    """

    scan_id: uuid.UUID
    overall: int
    ready: bool
    categories: list[PostureCategory] = []
    severity_counts: dict[str, int] = {}
    total_findings: int = 0
    new_findings: int = 0
    fixed_findings: int = 0
    unchanged_findings: int = 0
    top_risk_areas: list[PostureCategory] = []
    most_affected_files: list[AffectedFile] = []
    recommendations: list[str] = []


class RiskSummaryResponse(BaseModel):
    """Deterministic risk overview for a scan (active findings only).

    `counts` maps each priority band (immediate|high|normal|low) to how many
    active findings fall in it. `top` lists the highest-risk findings first.
    Suppressed (baselined) findings are excluded so accepted risks do not skew
    the picture.
    """

    scan_id: uuid.UUID
    total: int
    counts: dict[str, int]
    max_score: int = 0
    average_score: float = 0.0
    top: list[RiskSummaryItem] = []


class SuppressRequest(BaseModel):
    """Request to suppress (baseline) a finding across a repository."""

    reason: SuppressionReason
    note: str = Field(default="", max_length=1000)


class SuppressionRead(BaseModel):
    """A persisted suppression (baseline) entry."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    repository_name: str
    fingerprint: str
    rule_id: str
    file_path: str | None = None
    reason: SuppressionReason
    note: str
    created_at: datetime


class SuppressionListResponse(BaseModel):
    """Suppressions currently in effect for a repository."""

    repository_name: str
    total: int
    items: list[SuppressionRead]


class RepositoryFileContent(BaseModel):
    """A repository file's content for the code viewer (None if binary/oversized)."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    scan_id: uuid.UUID
    path: str
    file_type: str
    size: int
    content: str | None = None


class TopRule(BaseModel):
    """A frequently-occurring rule across all scans."""

    rule_id: str
    count: int


class StatsResponse(BaseModel):
    """Aggregate metrics for the dashboard."""

    total_scans: int
    repositories_scanned: int
    repositories_ready: int = 0
    critical_issues: int
    high_issues: int
    average_readiness: float
    total_findings: int = 0
    severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    top_rules: list[TopRule] = []
    latest_scans: list[ScanSummary]


# ---------------------------------------------------------------------------
# Remediation schemas
# ---------------------------------------------------------------------------


class RemediationStatus(str, Enum):
    """Whether a safe automatic fix could be proposed for a finding."""

    PROPOSED = "proposed"
    MANUAL_REQUIRED = "manual_required"


class RemediationProposal(BaseModel):
    """A proposed, non-destructive fix for a finding.

    Producing a proposal never mutates anything. When no safe deterministic fix
    exists, `status` is `manual_required` and the diff fields are empty.
    """

    finding_id: uuid.UUID
    rule_id: str
    status: RemediationStatus
    summary: str
    rationale: str
    confidence: Confidence
    file_path: str | None = None
    before: str | None = None
    after: str | None = None
    diff: str | None = None
    # Read-only recommended fix pattern for findings that cannot be auto-applied
    # safely (e.g. secrets). Guidance only - never applied to any file.
    guidance: str | None = None
    message: str


class RemediationResult(BaseModel):
    """The outcome of applying an approved fix to the stored file copy.

    The patch is applied only to the stored repository copy - never to any
    user repository. After patching, the file is re-scanned to verify the
    finding is genuinely resolved. `before_counts`/`after_counts` are the scan's
    severity distribution immediately before and after this remediation.
    """

    finding_id: uuid.UUID
    rule_id: str
    applied: bool
    resolved: bool
    remaining_rule_ids: list[str] = Field(default_factory=list)
    diff: str | None = None
    message: str
    severity: str | None = None
    before_counts: dict[str, int] = Field(default_factory=dict)
    after_counts: dict[str, int] = Field(default_factory=dict)


class RemediationHistoryItem(BaseModel):
    """One audit record of an approved remediation attempt."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    scan_id: uuid.UUID
    finding_id: uuid.UUID
    rule_id: str
    scanner: str
    file_path: str | None = None
    severity: str
    applied: bool
    resolved: bool
    remaining_rule_ids: list[str] = Field(default_factory=list)
    diff: str | None = None
    message: str
    before_counts: dict[str, int] = Field(default_factory=dict)
    after_counts: dict[str, int] = Field(default_factory=dict)
    created_at: datetime


class RemediationHistoryResponse(BaseModel):
    """A scan's remediation history, most recent first."""

    scan_id: uuid.UUID
    total: int
    resolved_count: int = 0
    items: list[RemediationHistoryItem] = []


# ---- Notifications ---------------------------------------------------------


class NotificationChannelCreateRequest(BaseModel):
    """Create a notification channel. ``config`` holds provider-specific fields.

    - slack/teams: {"webhook_url": "https://..."}
    - webhook:     {"url": "https://...", "secret": "optional"}
    - email:       {"recipients": ["a@b.com", ...]}
    """

    type: str  # slack | teams | webhook | email
    name: str
    config: dict = {}
    events: list[str] = []


class NotificationChannelUpdateRequest(BaseModel):
    name: str | None = None
    config: dict | None = None
    events: list[str] | None = None
    enabled: bool | None = None


class NotificationChannelRead(BaseModel):
    """A channel as returned by the API. Secret config values are masked."""

    id: uuid.UUID
    type: str
    name: str
    enabled: bool
    events: list[str] = []
    config: dict = {}  # masked - never contains full secrets
    created_at: datetime
    updated_at: datetime


class NotificationChannelListResponse(BaseModel):
    total: int
    items: list[NotificationChannelRead] = []


class NotificationDeliveryRead(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    channel_id: uuid.UUID
    event_type: str
    status: str
    error: str | None = None
    created_at: datetime


# ---- Audit log -------------------------------------------------------------


class AuditLogRead(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    action: str
    resource_type: str
    resource_id: str | None = None
    actor: str
    status: str
    detail: dict | None = None
    created_at: datetime


class AuditLogListResponse(BaseModel):
    total: int
    items: list[AuditLogRead] = []


# ---- Phase 3: AI investigations --------------------------------------------


class InvestigationRequest(BaseModel):
    """A natural-language investigation question."""

    question: str = Field(min_length=1, max_length=1000)


class RepositoryInvestigationRequest(BaseModel):
    repository: str = Field(min_length=1)
    question: str = Field(min_length=1, max_length=1000)


class InvestigationResponse(BaseModel):
    """The engine's evidence-grounded result. ``label`` marks it as AI analysis,
    never a deterministic finding; ``confidence`` is deterministic/evidence-based."""

    investigation_id: str | None = None
    question: str
    answer: str
    root_cause: str = ""
    impact: str = ""
    recommendations: list[str] = []
    confidence: str = "low"
    cited_finding_ids: list[str] = []
    cited_files: list[str] = []
    citations: list[dict] = []
    evidence: list[dict] = []
    trace: list[dict] = []
    label: str = "AI Insight"
    ai_used: bool = False
    tool_calls: int = 0
    hallucination_guard_triggered: bool = False


class InvestigationSummary(BaseModel):
    """A row in the investigation history list."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    scope: str
    scan_id: uuid.UUID | None = None
    finding_id: uuid.UUID | None = None
    repository_name: str = ""
    question: str
    confidence: str = "low"
    label: str = "AI Insight"
    ai_used: bool = False
    tool_calls: int = 0
    created_at: datetime


class InvestigationListResponse(BaseModel):
    total: int
    items: list[InvestigationSummary] = []


class InvestigationDetail(BaseModel):
    """A reopened investigation session with its full evidence + trace."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    scope: str
    scan_id: uuid.UUID | None = None
    finding_id: uuid.UUID | None = None
    repository_name: str = ""
    question: str
    answer: str = ""
    root_cause: str = ""
    impact: str = ""
    confidence: str = "low"
    label: str = "AI Insight"
    recommendations: list = []
    citations: list = []
    evidence: list = []
    trace: list = []
    ai_used: bool = False
    tool_calls: int = 0
    hallucination_guard_triggered: bool = False
    created_at: datetime


class RemediationPlanRequest(BaseModel):
    """Request a remediation plan. Omit finding_ids to auto-select by risk."""

    finding_ids: list[uuid.UUID] | None = None
    max_targets: int = Field(default=5, ge=1, le=8)


class RemediationStepResponse(BaseModel):
    order: int
    action: str
    finding_id: str
    rule_id: str
    file: str | None = None
    deterministic_recommendation: str = ""


class RemediationPlanResponse(BaseModel):
    """A proposed remediation plan. Always requires approval; never auto-applied."""

    scan_id: str
    problem: str
    root_cause: str = ""
    steps: list[RemediationStepResponse] = []
    affected_files: list[str] = []
    expected_findings_resolved: list[str] = []
    estimated_score_before: int = 0
    estimated_score_after: int = 0
    estimated_score_delta: int = 0
    estimate_note: str = ""
    risk_level: str = "low"
    requires_approval: bool = True
    status: str = "proposed"
    label: str = "AI Remediation Plan"
    ai_used: bool = False
    confidence: str = "low"


class AIReviewItemResponse(BaseModel):
    title: str
    concern: str
    category: str = "security"
    confidence: str = "low"
    files: list[str] = []
    source: str = "AI_REVIEW"
    authoritative: bool = False


class AIReviewResponse(BaseModel):
    """Non-authoritative AI review output (PR or security). Never fails a gate."""

    label: str = "AI Review"
    authoritative: bool = False
    ai_used: bool = False
    note: str = ""
    items: list[AIReviewItemResponse] = []
    pr_scan_id: str | None = None
    scan_id: str | None = None
