"""Scan-level investigation tools: scan summary and scan history."""

from __future__ import annotations

import uuid

from pydantic import Field

from agents.investigation.tools._common import load_findings_with_paths, load_scan
from agents.investigation.tools.base import (
    InvestigationTool,
    ToolArgs,
    ToolContext,
    ToolResult,
    clamp_limit,
)
from services.scan_service import ScanService


def _v(enum_or_str: object) -> str:
    return enum_or_str.value if hasattr(enum_or_str, "value") else str(enum_or_str)


class _ScanArgs(ToolArgs):
    scan_id: uuid.UUID = Field(description="The scan to inspect.")


class GetScanSummaryTool(InvestigationTool):
    name = "get_scan_summary"
    description = (
        "Deterministic high-level summary of a scan: repository, status, "
        "production-readiness score, severity/category counts, weakest posture "
        "domains, and top recommended actions. Start here for scan questions."
    )
    args_schema = _ScanArgs

    async def _run(self, ctx: ToolContext, args: _ScanArgs) -> ToolResult:  # type: ignore[override]
        scan = await load_scan(ctx.session, args.scan_id)
        items = await load_findings_with_paths(ctx.session, args.scan_id)
        severity_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        for finding, _ in items:
            sv = _v(finding.severity)
            cat = _v(finding.category)
            severity_counts[sv] = severity_counts.get(sv, 0) + 1
            category_counts[cat] = category_counts.get(cat, 0) + 1

        posture = await ScanService(ctx.session, ctx.settings).get_posture(args.scan_id)
        categories = [
            {"domain": c.get("label") or c.get("key"), "score": c.get("score")}
            for c in posture.get("categories", [])
        ]
        data = {
            "scan_id": str(scan.id),
            "repository": scan.repository_name,
            "status": _v(scan.status),
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "production_readiness": posture.get("overall"),
            "ready": posture.get("ready"),
            "total_findings": len(items),
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "posture_domains": categories,
            "recommendations": (posture.get("recommendations") or [])[:5],
        }
        return ToolResult(data=data, returned=1)


class _HistoryArgs(ToolArgs):
    scan_id: uuid.UUID = Field(description="A scan in the repository whose history to retrieve.")
    limit: int = Field(default=10, description="Max number of recent scans (<=30).")


class GetScanHistoryTool(InvestigationTool):
    name = "get_scan_history"
    description = (
        "Historical trend of a repository's completed scans (readiness score, "
        "severity distribution, and new/fixed deltas over time). Use to answer "
        "'why did the score change' and trend questions."
    )
    args_schema = _HistoryArgs

    async def _run(self, ctx: ToolContext, args: _HistoryArgs) -> ToolResult:  # type: ignore[override]
        await load_scan(ctx.session, args.scan_id)
        limit = clamp_limit(args.limit, default=10, maximum=30)
        trends = await ScanService(ctx.session, ctx.settings).get_trends(args.scan_id, limit=limit)
        points = trends.get("points", trends) if isinstance(trends, dict) else trends
        count = len(points) if isinstance(points, list) else 1
        return ToolResult(data=trends, returned=count)
