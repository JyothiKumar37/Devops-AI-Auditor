"""Dashboard statistics endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from api.dependencies import ScanServiceDep
from models.schemas import ScanSummary, StatsResponse

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("", response_model=StatsResponse, summary="Aggregate dashboard metrics")
async def get_stats(service: ScanServiceDep) -> StatsResponse:
    data = await service.get_stats()
    readiness_by_scan = data.pop("readiness_by_scan", {})
    latest = [
        ScanSummary(
            id=scan.id,
            repository_name=scan.repository_name,
            source_type=scan.source_type,
            status=scan.status,
            created_at=scan.created_at,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            error_message=scan.error_message,
            file_count=count,
            readiness=readiness_by_scan.get(scan.id),
        )
        for scan, count in data.pop("latest_scans")
    ]
    return StatsResponse(latest_scans=latest, **data)
