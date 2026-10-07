"""Analysis + repository tools: posture, risk, scan diff, file view, search."""

from __future__ import annotations

import uuid

from pydantic import Field
from sqlalchemy import select

from agents.investigation.redaction import redact_secrets
from agents.investigation.tools._common import load_findings_with_paths, load_scan
from agents.investigation.tools.base import (
    MAX_FILE_LINES,
    MAX_SEARCH_MATCHES,
    InvestigationTool,
    ToolArgs,
    ToolContext,
    ToolError,
    ToolResult,
    clamp_limit,
)
from agents.reasoning.sanitize import neutralize
from models.scan import RepositoryFile
from services.risk import RiskInput, assess_risk
from services.scan_service import ScanService


def _v(enum_or_str: object) -> str:
    return enum_or_str.value if hasattr(enum_or_str, "value") else str(enum_or_str)


class _ScanArgs(ToolArgs):
    scan_id: uuid.UUID = Field(description="The scan to analyse.")


class GetPostureTool(InvestigationTool):
    name = "get_posture"
    description = (
        "Deterministic production-readiness and per-domain posture scores "
        "(security, kubernetes, containers, terraform, cicd, reliability, "
        "secrets, dependencies, infrastructure), weakest areas, and most-affected "
        "files. Authoritative scores - never recompute these yourself."
    )
    args_schema = _ScanArgs

    async def _run(self, ctx: ToolContext, args: _ScanArgs) -> ToolResult:  # type: ignore[override]
        await load_scan(ctx.session, args.scan_id)
        posture = await ScanService(ctx.session, ctx.settings).get_posture(args.scan_id)
        return ToolResult(data=posture, returned=1)


class _RiskArgs(ToolArgs):
    scan_id: uuid.UUID = Field(description="The scan to analyse.")
    limit: int = Field(default=20, description="Max findings to rank (<=50).")


class GetRiskSummaryTool(InvestigationTool):
    name = "get_risk_summary"
    description = (
        "Deterministic per-finding risk ranking (0-100 score + priority) for a "
        "scan, highest risk first. Risk reflects exploitability, exposure, "
        "production impact and recurrence - not just nominal severity."
    )
    args_schema = _RiskArgs

    async def _run(self, ctx: ToolContext, args: _RiskArgs) -> ToolResult:  # type: ignore[override]
        await load_scan(ctx.session, args.scan_id)
        items = await load_findings_with_paths(ctx.session, args.scan_id)
        recurrence: dict[str, int] = {}
        for finding, _ in items:
            recurrence[finding.rule_id] = recurrence.get(finding.rule_id, 0) + 1

        ranked: list[tuple[int, dict]] = []
        for finding, path in items:
            assessment = assess_risk(
                RiskInput(
                    rule_id=finding.rule_id,
                    scanner=finding.scanner,
                    category=_v(finding.category),
                    severity=_v(finding.severity),
                    confidence=_v(finding.confidence),
                    title=finding.title,
                    description=finding.description,
                    evidence=finding.evidence,
                    file_path=path,
                    recurrence=recurrence.get(finding.rule_id, 1),
                )
            )
            ranked.append(
                (
                    assessment.score,
                    {
                        "finding_id": str(finding.id),
                        "rule_id": finding.rule_id,
                        "severity": _v(finding.severity),
                        "title": neutralize(finding.title, max_length=200),
                        "file": neutralize(path, max_length=200) if path else None,
                        "risk_score": assessment.score,
                        "priority": assessment.priority,
                        "signals": assessment.signals[:5],
                        "is_ai_review": finding.scanner == "ai-review",
                    },
                )
            )
        ranked.sort(key=lambda r: -r[0])
        limit = clamp_limit(args.limit)
        top = [entry for _, entry in ranked[:limit]]
        return ToolResult(
            data=top, returned=len(top), total_available=len(ranked), truncated=len(ranked) > limit
        )


class _DiffArgs(ToolArgs):
    scan_id: uuid.UUID = Field(description="The head scan to compare.")
    base_scan_id: uuid.UUID | None = Field(
        default=None, description="Optional base scan; defaults to the previous completed scan."
    )


class GetScanDiffTool(InvestigationTool):
    name = "get_scan_diff"
    description = (
        "Deterministic diff of a scan versus a prior scan: new vs fixed vs "
        "unchanged findings, severity deltas, and the readiness score change. Use "
        "to explain what changed and why the score moved."
    )
    args_schema = _DiffArgs

    async def _run(self, ctx: ToolContext, args: _DiffArgs) -> ToolResult:  # type: ignore[override]
        await load_scan(ctx.session, args.scan_id)
        if args.base_scan_id is not None and not ctx.authorizes_scan(args.base_scan_id):
            raise ToolError(
                f"Base scan {args.base_scan_id} is outside the authorized scope.",
                code="unauthorized",
            )
        svc = ScanService(ctx.session, ctx.settings)
        diff = await svc.get_diff(args.scan_id, args.base_scan_id)
        data = {
            "base_scan_id": str(diff["base_scan_id"]) if diff.get("base_scan_id") else None,
            "head_scan_id": str(diff.get("head_scan_id")),
            "base_readiness": diff.get("base_readiness"),
            "head_readiness": diff.get("head_readiness"),
            "readiness_delta": diff.get("readiness_delta"),
            "summary": diff.get("summary"),
            "new_severity_counts": diff.get("new_severity_counts"),
            "fixed_severity_counts": diff.get("fixed_severity_counts"),
            "new_findings": [
                _trim_diff_item(i) for i in (diff.get("new_findings") or [])[:MAX_SEARCH_MATCHES]
            ],
            "fixed_findings": [
                _trim_diff_item(i)
                for i in (diff.get("fixed_findings") or [])[:MAX_SEARCH_MATCHES]
            ],
        }
        return ToolResult(data=data, returned=1)


def _trim_diff_item(item: dict) -> dict:
    """Keep only safe, neutralized fields from a diff finding item."""
    out: dict[str, object] = {}
    for key in ("rule_id", "scanner", "severity", "category", "line"):
        if key in item:
            out[key] = item[key]
    for key in ("title", "file", "path"):
        if key in item and isinstance(item[key], str):
            out[key] = neutralize(item[key], max_length=200)
    return out


class _FileArgs(ToolArgs):
    scan_id: uuid.UUID = Field(description="The scan the file belongs to.")
    path: str = Field(description="Repository-relative file path (as reported in findings).")
    start_line: int | None = Field(default=None, description="1-based first line to return.")
    end_line: int | None = Field(default=None, description="1-based last line to return.")


class GetFileTool(InvestigationTool):
    name = "get_file"
    description = (
        "Return a bounded, secret-redacted slice of a repository file's text with "
        "line numbers. Prefer a start_line/end_line window around a finding. Binary "
        "or oversized files return no content."
    )
    args_schema = _FileArgs

    async def _run(self, ctx: ToolContext, args: _FileArgs) -> ToolResult:  # type: ignore[override]
        await load_scan(ctx.session, args.scan_id)
        repo_file = await ctx.session.scalar(
            select(RepositoryFile).where(
                RepositoryFile.scan_id == args.scan_id, RepositoryFile.path == args.path
            )
        )
        if repo_file is None:
            raise ToolError(
                f"File '{args.path}' not found in scan {args.scan_id}.", code="not_found"
            )
        if repo_file.content is None:
            return ToolResult(
                data={"path": args.path, "content": None, "note": "No stored text content."},
                returned=0,
                note="binary_or_oversized",
            )
        lines = repo_file.content.splitlines()
        total = len(lines)
        start = max((args.start_line or 1) - 1, 0)
        if args.end_line and args.end_line >= (args.start_line or 1):
            end = min(args.end_line, total)
        else:
            end = min(start + MAX_FILE_LINES, total)
        end = min(end, start + MAX_FILE_LINES)
        window = lines[start:end]
        numbered = "\n".join(
            f"{start + i + 1}: {redact_secrets(line)}" for i, line in enumerate(window)
        )
        return ToolResult(
            data={
                "path": args.path,
                "start_line": start + 1,
                "end_line": start + len(window),
                "total_lines": total,
                "content": neutralize(numbered, max_length=6000),
            },
            returned=len(window),
            total_available=total,
            truncated=end < total,
        )


class _SearchArgs(ToolArgs):
    scan_id: uuid.UUID = Field(description="The scan whose files to search.")
    query: str = Field(description="Case-insensitive substring to search for.", min_length=2)
    limit: int = Field(default=20, description="Max matches to return (<=50).")


class SearchRepositoryTool(InvestigationTool):
    name = "search_repository"
    description = (
        "Case-insensitive substring search across the scan's stored text files. "
        "Returns bounded, secret-redacted matches with file path and line number. "
        "Use to locate configuration keys, image tags, or settings."
    )
    args_schema = _SearchArgs

    async def _run(self, ctx: ToolContext, args: _SearchArgs) -> ToolResult:  # type: ignore[override]
        await load_scan(ctx.session, args.scan_id)
        needle = args.query.strip().lower()
        limit = clamp_limit(args.limit, maximum=MAX_SEARCH_MATCHES)
        rows = await ctx.session.scalars(
            select(RepositoryFile).where(RepositoryFile.scan_id == args.scan_id)
        )
        matches: list[dict] = []
        total = 0
        for repo_file in rows:
            if not repo_file.content:
                continue
            for lineno, line in enumerate(repo_file.content.splitlines(), start=1):
                if needle in line.lower():
                    total += 1
                    if len(matches) < limit:
                        matches.append(
                            {
                                "path": neutralize(repo_file.path, max_length=200),
                                "line": lineno,
                                "text": neutralize(redact_secrets(line.strip()), max_length=240),
                            }
                        )
        return ToolResult(
            data=matches,
            returned=len(matches),
            total_available=total,
            truncated=total > len(matches),
        )
