"""Scan ingestion and query endpoints.

- `POST /scans/upload`        : upload a repository ZIP for ingestion.
- `GET  /scans`               : list scans (most recent first).
- `GET  /scans/{scan_id}`     : fetch a single scan.
- `GET  /scans/{scan_id}/files`: list the files discovered for a scan.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, File, Query, Response, UploadFile, status

from agents.reasoning import AuditReport, ReasoningService
from api.dependencies import (
    DbSessionDep,
    RemediationServiceDep,
    ReportServiceDep,
    ScanServiceDep,
    SettingsDep,
)
from models.scan import Scan
from models.schemas import (
    DiscoveryResponse,
    FindingRead,
    FindingsResponse,
    GitScanRequest,
    RemediationProposal,
    RemediationResult,
    RepositoryFileContent,
    RepositoryFileRead,
    ScanDiffResponse,
    ScanFilesResponse,
    ScanListResponse,
    ScanSummary,
)
from services.report import ReportFormat

router = APIRouter(prefix="/scans", tags=["scans"])


def _to_summary(scan: Scan, file_count: int) -> ScanSummary:
    return ScanSummary(
        id=scan.id,
        repository_name=scan.repository_name,
        source_type=scan.source_type,
        status=scan.status,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
        file_count=file_count,
    )


@router.post(
    "/upload",
    response_model=ScanSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a repository ZIP archive for ingestion",
)
async def upload_scan(
    service: ScanServiceDep,
    file: UploadFile = File(..., description="A .zip archive of the repository."),
) -> ScanSummary:
    scan, file_count = await service.ingest_zip_upload(
        filename=file.filename,
        upload_stream=file.file,
    )
    return _to_summary(scan, file_count)


@router.post(
    "/git",
    response_model=ScanSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Clone and ingest a repository from a git URL",
)
async def ingest_git_scan(
    request: GitScanRequest,
    service: ScanServiceDep,
) -> ScanSummary:
    """Clone a repository from an http(s) git URL and run the full scan pipeline.

    The clone is shallow, single-branch and non-interactive; repository code is
    never executed and the working tree is discarded once analysis completes.
    """
    scan, file_count = await service.ingest_git_repo(
        repository_url=request.repository_url,
        ref=request.ref,
    )
    return _to_summary(scan, file_count)


@router.get("", response_model=ScanListResponse, summary="List scans")
async def list_scans(
    service: ScanServiceDep,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> ScanListResponse:
    rows, total = await service.list_scans(limit=limit, offset=offset)
    return ScanListResponse(
        items=[_to_summary(scan, count) for scan, count in rows],
        total=total,
    )


@router.get("/{scan_id}", response_model=ScanSummary, summary="Get a scan")
async def get_scan(scan_id: uuid.UUID, service: ScanServiceDep) -> ScanSummary:
    scan, file_count = await service.get_scan(scan_id)
    return _to_summary(scan, file_count)


@router.get(
    "/{scan_id}/files",
    response_model=ScanFilesResponse,
    summary="List files discovered for a scan",
)
async def get_scan_files(
    scan_id: uuid.UUID,
    service: ScanServiceDep,
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
) -> ScanFilesResponse:
    files, total = await service.get_files(scan_id, limit=limit, offset=offset)
    return ScanFilesResponse(
        scan_id=scan_id,
        total=total,
        items=[RepositoryFileRead.model_validate(f) for f in files],
    )


@router.get(
    "/{scan_id}/diff",
    response_model=ScanDiffResponse,
    summary="Compare a scan's findings against a previous or explicit base scan",
)
async def get_scan_diff(
    scan_id: uuid.UUID,
    service: ScanServiceDep,
    base: uuid.UUID | None = Query(
        None,
        description=(
            "Explicit base scan to compare against. Defaults to the most recent "
            "completed scan of the same repository created before this one."
        ),
    ),
) -> ScanDiffResponse:
    """Diff this scan (head) against a base scan: new, fixed and unchanged findings.

    Findings are matched by a line-independent fingerprint, and the deterministic
    production-readiness score is reported for both sides with its delta.
    """
    result = await service.get_diff(scan_id, base)
    return ScanDiffResponse.model_validate(result)


@router.get(
    "/{scan_id}/discovery",
    response_model=DiscoveryResponse,
    summary="Get discovered files grouped by category",
)
async def get_scan_discovery(scan_id: uuid.UUID, service: ScanServiceDep) -> DiscoveryResponse:
    groups, total = await service.get_discovery(scan_id)
    categories = {
        category: [RepositoryFileRead.model_validate(f) for f in files]
        for category, files in groups.items()
    }
    counts = {category: len(files) for category, files in groups.items()}
    return DiscoveryResponse(
        scan_id=scan_id,
        total=total,
        counts=counts,
        categories=categories,
    )


@router.get(
    "/{scan_id}/files/{file_id}/content",
    response_model=RepositoryFileContent,
    summary="Get a repository file's content (for the code viewer)",
)
async def get_scan_file_content(
    scan_id: uuid.UUID,
    file_id: uuid.UUID,
    service: ScanServiceDep,
) -> RepositoryFileContent:
    repo_file = await service.get_file(scan_id, file_id)
    return RepositoryFileContent.model_validate(repo_file)


@router.get(
    "/{scan_id}/report",
    response_model=AuditReport,
    summary="Generate the AI reasoning report for a scan",
)
async def get_scan_report(
    scan_id: uuid.UUID,
    session: DbSessionDep,
    settings: SettingsDep,
) -> AuditReport:
    service = ReasoningService(session=session, settings=settings)
    report = await service.generate_report(scan_id)
    return AuditReport.model_validate(report)


@router.get(
    "/{scan_id}/report/export",
    summary="Export the audit report as JSON, HTML, or PDF",
    responses={
        200: {
            "content": {
                "application/json": {},
                "text/html": {},
                "application/pdf": {},
            },
            "description": "The rendered report in the requested format.",
        }
    },
)
async def export_scan_report(
    scan_id: uuid.UUID,
    service: ReportServiceDep,
    format: ReportFormat = Query(
        ReportFormat.JSON, description="Export format: json, html, or pdf."
    ),
    download: bool = Query(
        True, description="Send as a file download (Content-Disposition: attachment)."
    ),
) -> Response:
    """Render the full audit report (all sections) in the requested format.

    The JSON form is the stable, machine-readable representation; HTML and PDF
    are human-facing views of the same underlying model.
    """
    content, media_type, filename = await service.render(scan_id, format)
    disposition = "attachment" if download else "inline"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'{disposition}; filename="{filename}"'},
    )


@router.get(
    "/{scan_id}/findings",
    response_model=FindingsResponse,
    summary="Retrieve scanner findings for a scan",
)
async def get_scan_findings(
    scan_id: uuid.UUID,
    service: ScanServiceDep,
    severity: str | None = Query(None, description="Filter by severity (e.g. high)."),
    category: str | None = Query(None, description="Filter by finding category."),
    scanner: str | None = Query(None, description="Filter by scanner."),
    confidence: str | None = Query(None, description="Filter by confidence."),
    file_id: uuid.UUID | None = Query(None, description="Filter by repository file id."),
    file_type: str | None = Query(None, description="Filter by file type."),
) -> FindingsResponse:
    findings, severity_counts = await service.get_findings(
        scan_id,
        severity=severity,
        category=category,
        scanner=scanner,
        confidence=confidence,
        file_id=file_id,
        file_type=file_type,
    )
    return FindingsResponse(
        scan_id=scan_id,
        total=len(findings),
        severity_counts=severity_counts,
        items=[FindingRead.model_validate(f) for f in findings],
    )


@router.post(
    "/{scan_id}/findings/{finding_id}/remediation",
    response_model=RemediationProposal,
    summary="Generate a proposed fix for a finding (no changes are made)",
)
async def propose_remediation(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    service: RemediationServiceDep,
) -> RemediationProposal:
    """Generate a fix proposal (diff) for review. This never modifies anything."""
    return await service.propose(scan_id, finding_id)


@router.post(
    "/{scan_id}/findings/{finding_id}/remediation/apply",
    response_model=RemediationResult,
    summary="Apply an approved fix to the stored file copy and verify resolution",
)
async def apply_remediation(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    service: RemediationServiceDep,
) -> RemediationResult:
    """Apply the approved fix to the stored copy only, then re-scan to verify.

    This endpoint represents explicit user approval: the frontend calls it only
    after the user reviews the diff and approves. No user repository is touched.
    """
    return await service.apply(scan_id, finding_id)
