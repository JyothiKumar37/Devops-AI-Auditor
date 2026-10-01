"""Read endpoints for tracked pull/merge requests and their scan results."""

from __future__ import annotations

import uuid

from fastapi import APIRouter
from sqlalchemy import select

from api.dependencies import DbSessionDep
from core.exceptions import NotFoundError
from models.pullrequest import PullRequest, PullRequestScan
from models.schemas import (
    PullRequestDetail,
    PullRequestListResponse,
    PullRequestRead,
    PullRequestScanRead,
)

router = APIRouter(prefix="/pull-requests", tags=["pull-requests"])


@router.get("", response_model=PullRequestListResponse, summary="List tracked PRs")
async def list_pull_requests(
    session: DbSessionDep, repo: str | None = None
) -> PullRequestListResponse:
    stmt = select(PullRequest).order_by(PullRequest.updated_at.desc())
    if repo:
        stmt = stmt.where(PullRequest.repo_full_name == repo)
    rows = (await session.scalars(stmt)).all()
    return PullRequestListResponse(
        total=len(rows), items=[PullRequestRead.model_validate(r) for r in rows]
    )


@router.get(
    "/{pull_request_id}",
    response_model=PullRequestDetail,
    summary="Get a PR with its scan history",
)
async def get_pull_request(
    pull_request_id: uuid.UUID, session: DbSessionDep
) -> PullRequestDetail:
    pr = await session.get(PullRequest, pull_request_id)
    if pr is None:
        raise NotFoundError(f"Pull request {pull_request_id} not found.")
    scans = (
        await session.scalars(
            select(PullRequestScan)
            .where(PullRequestScan.pull_request_id == pr.id)
            .order_by(PullRequestScan.created_at.desc())
        )
    ).all()
    scan_reads = [PullRequestScanRead.model_validate(s) for s in scans]
    return PullRequestDetail(
        pull_request=PullRequestRead.model_validate(pr),
        latest_scan=scan_reads[0] if scan_reads else None,
        scans=scan_reads,
    )
