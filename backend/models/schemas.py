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


class ScanListResponse(BaseModel):
    """Paginated list of scans."""

    items: list[ScanSummary]
    total: int


class ScanFilesResponse(BaseModel):
    """The files discovered for a scan."""

    scan_id: uuid.UUID
    total: int
    items: list[RepositoryFileRead]


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

from models.enums import Confidence, FindingCategory, Severity  # noqa: E402


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


class FindingsResponse(BaseModel):
    """A list of findings for a scan, with per-severity counts."""

    scan_id: uuid.UUID
    total: int
    severity_counts: dict[str, int]
    items: list[FindingRead]


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
    message: str


class RemediationResult(BaseModel):
    """The outcome of applying an approved fix to the stored file copy.

    The patch is applied only to the stored repository copy - never to any
    user repository. After patching, the file is re-scanned to verify the
    finding is genuinely resolved.
    """

    finding_id: uuid.UUID
    rule_id: str
    applied: bool
    resolved: bool
    remaining_rule_ids: list[str] = Field(default_factory=list)
    diff: str | None = None
    message: str
