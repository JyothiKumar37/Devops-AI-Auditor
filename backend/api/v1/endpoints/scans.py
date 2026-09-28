"""Scan ingestion and query endpoints.

- `POST /scans/upload`        : upload a repository ZIP for ingestion.
- `GET  /scans`               : list scans (most recent first).
- `GET  /scans/{scan_id}`     : fetch a single scan.
- `GET  /scans/{scan_id}/files`: list the files discovered for a scan.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator

from fastapi import APIRouter, File, Query, Request, Response, UploadFile, status
from starlette.responses import StreamingResponse

from agents.reasoning import AuditReport, ReasoningService
from api.dependencies import (
    DbSessionDep,
    RemediationServiceDep,
    ReportServiceDep,
    ScanServiceDep,
    SettingsDep,
    SuppressionServiceDep,
)
from core.exceptions import NotFoundError
from models.enums import ScanStatus
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
    SuppressionListResponse,
    SuppressionRead,
    SuppressRequest,
)
from services.report import ReportFormat
from services.scan_service import ScanService
from workers.tasks import run_git_scan, run_zip_scan

router = APIRouter(prefix="/scans", tags=["scans"])

# Server-sent-events tuning for the scan status stream.
_STREAM_POLL_SECONDS = 1.0
_STREAM_MAX_SECONDS = 900
_TERMINAL_STATUSES = {ScanStatus.COMPLETED, ScanStatus.FAILED}


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
    settings: SettingsDep,
    file: UploadFile = File(..., description="A .zip archive of the repository."),
) -> ScanSummary:
    if settings.scan_async:
        # Persist the upload, return a PENDING scan, and process on the worker.
        scan = await service.create_zip_scan(
            filename=file.filename, upload_stream=file.file
        )
        run_zip_scan.delay(str(scan.id))
        return _to_summary(scan, 0)

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
    settings: SettingsDep,
) -> ScanSummary:
    """Clone a repository from an http(s) git URL and run the full scan pipeline.

    The clone is shallow, single-branch and non-interactive; repository code is
    never executed and the working tree is discarded once analysis completes.
    """
    if settings.scan_async:
        scan = await service.create_git_scan(
            repository_url=request.repository_url, ref=request.ref
        )
        run_git_scan.delay(str(scan.id), request.repository_url, request.ref)
        return _to_summary(scan, 0)

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
    "/{scan_id}/stream",
    summary="Stream a scan's status until it reaches a terminal state (SSE)",
)
async def stream_scan(
    scan_id: uuid.UUID,
    request: Request,
    service: ScanServiceDep,
) -> StreamingResponse:
    """Server-sent-events stream of a scan's status.

    Emits a `ScanSummary` payload immediately and again on every change, closing
    once the scan completes or fails. Lets the UI flip to results the moment a
    worker finishes, rather than waiting for the next poll. Each poll uses a
    short-lived session so it sees the worker's committed updates.
    """
    # 404 up front if the scan does not exist (before opening the stream).
    await service.get_scan(scan_id)
    database = request.app.state.database
    settings = request.app.state.settings

    async def events() -> AsyncIterator[str]:
        last_payload: str | None = None
        polls = int(_STREAM_MAX_SECONDS / _STREAM_POLL_SECONDS)
        for _ in range(polls):
            async with database.sessionmaker() as session:
                scoped = ScanService(session=session, settings=settings)
                try:
                    scan, file_count = await scoped.get_scan(scan_id)
                except NotFoundError:
                    yield 'event: error\ndata: {"error": "scan not found"}\n\n'
                    return
                payload = _to_summary(scan, file_count).model_dump_json()
                terminal = scan.status in _TERMINAL_STATUSES
            if payload != last_payload:
                last_payload = payload
                yield f"data: {payload}\n\n"
            if terminal:
                return
            await asyncio.sleep(_STREAM_POLL_SECONDS)
        yield 'event: timeout\ndata: {}\n\n'

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


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
    summary="Export the audit report as JSON, HTML, PDF, or SARIF",
    responses={
        200: {
            "content": {
                "application/json": {},
                "text/html": {},
                "application/pdf": {},
                "application/sarif+json": {},
            },
            "description": "The rendered report in the requested format.",
        }
    },
)
async def export_scan_report(
    scan_id: uuid.UUID,
    service: ReportServiceDep,
    format: ReportFormat = Query(
        ReportFormat.JSON, description="Export format: json, html, pdf, or sarif."
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
    suppressed: bool | None = Query(
        None,
        description="Filter by baseline status: true = only suppressed, false = only active.",
    ),
) -> FindingsResponse:
    findings, severity_counts, suppressed_count = await service.get_findings(
        scan_id,
        severity=severity,
        category=category,
        scanner=scanner,
        confidence=confidence,
        file_id=file_id,
        file_type=file_type,
        suppressed=suppressed,
    )
    return FindingsResponse(
        scan_id=scan_id,
        total=len(findings),
        severity_counts=severity_counts,
        suppressed_count=suppressed_count,
        items=[FindingRead.model_validate(f) for f in findings],
    )


@router.post(
    "/{scan_id}/findings/{finding_id}/suppress",
    response_model=SuppressionRead,
    status_code=status.HTTP_201_CREATED,
    summary="Suppress (baseline) a finding for its repository",
)
async def suppress_finding(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    request: SuppressRequest,
    service: SuppressionServiceDep,
) -> SuppressionRead:
    """Baseline a finding as false-positive / accepted-risk / won't-fix.

    The decision is scoped to the repository and re-applied to future scans.
    """
    suppression = await service.suppress(
        scan_id, finding_id, request.reason, request.note
    )
    return SuppressionRead.model_validate(suppression)


@router.delete(
    "/{scan_id}/findings/{finding_id}/suppress",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a finding's baseline (un-suppress)",
)
async def unsuppress_finding(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    service: SuppressionServiceDep,
) -> Response:
    await service.unsuppress(scan_id, finding_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{scan_id}/suppressions",
    response_model=SuppressionListResponse,
    summary="List suppressions in effect for the scan's repository",
)
async def list_suppressions(
    scan_id: uuid.UUID,
    service: SuppressionServiceDep,
) -> SuppressionListResponse:
    scan, items = await service.list_for_scan(scan_id)
    return SuppressionListResponse(
        repository_name=scan.repository_name,
        total=len(items),
        items=[SuppressionRead.model_validate(s) for s in items],
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
