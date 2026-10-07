"""Finding-level investigation tools: list, detail, and related findings."""

from __future__ import annotations

import uuid

from pydantic import Field

from agents.investigation.tools._common import (
    finding_to_dict,
    load_findings_with_paths,
    load_scan,
)
from agents.investigation.tools.base import (
    DEFAULT_LIMIT,
    InvestigationTool,
    ToolArgs,
    ToolContext,
    ToolError,
    ToolResult,
    clamp_limit,
)
from models.enums import FindingCategory, Severity


class _GetFindingsArgs(ToolArgs):
    scan_id: uuid.UUID = Field(description="The scan whose findings to list.")
    severity: str | None = Field(default=None, description="Filter: info|low|medium|high|critical.")
    category: str | None = Field(default=None, description="Filter by finding category.")
    scanner: str | None = Field(default=None, description="Filter by scanner name.")
    limit: int = Field(default=DEFAULT_LIMIT, description="Max findings to return (<=50).")
    offset: int = Field(default=0, description="Pagination offset.")


class GetFindingsTool(InvestigationTool):
    name = "get_findings"
    description = (
        "List deterministic findings for a scan, newest/most-severe first, with "
        "optional filters (severity, category, scanner) and pagination. Returns a "
        "bounded page; use offset to page through more."
    )
    args_schema = _GetFindingsArgs

    async def _run(self, ctx: ToolContext, args: _GetFindingsArgs) -> ToolResult:  # type: ignore[override]
        await load_scan(ctx.session, args.scan_id)
        items = await load_findings_with_paths(ctx.session, args.scan_id)

        if args.severity:
            sev = _validate_choice(args.severity, {s.value for s in Severity}, "severity")
            items = [it for it in items if _v(it[0].severity) == sev]
        if args.category:
            cat = _validate_choice(args.category, {c.value for c in FindingCategory}, "category")
            items = [it for it in items if _v(it[0].category) == cat]
        if args.scanner:
            items = [it for it in items if it[0].scanner == args.scanner]

        total = len(items)
        offset = max(args.offset, 0)
        limit = clamp_limit(args.limit)
        page = items[offset : offset + limit]
        data = [finding_to_dict(f, p, include_evidence=False) for f, p in page]
        return ToolResult(
            data=data,
            returned=len(data),
            total_available=total,
            truncated=offset + len(data) < total,
        )


class _GetFindingArgs(ToolArgs):
    scan_id: uuid.UUID = Field(description="The scan the finding belongs to.")
    finding_id: uuid.UUID = Field(description="The finding to retrieve in full.")


class GetFindingTool(InvestigationTool):
    name = "get_finding"
    description = (
        "Full detail of ONE finding (title, description, evidence [secret-redacted], "
        "recommendation, file, line, scanner, severity). Use get_file to view the "
        "surrounding code."
    )
    args_schema = _GetFindingArgs

    async def _run(self, ctx: ToolContext, args: _GetFindingArgs) -> ToolResult:  # type: ignore[override]
        items = await load_findings_with_paths(ctx.session, args.scan_id)
        for finding, path in items:
            if finding.id == args.finding_id:
                return ToolResult(data=finding_to_dict(finding, path), returned=1)
        raise ToolError(
            f"Finding {args.finding_id} not found in scan {args.scan_id}.", code="not_found"
        )


class _RootCauseArgs(ToolArgs):
    scan_id: uuid.UUID = Field(description="The scan to cluster into root-cause groups.")


class GetRootCauseGroupsTool(InvestigationTool):
    name = "get_root_cause_groups"
    description = (
        "Deterministically cluster a scan's findings into themed root-cause groups "
        "(e.g. 'Kubernetes resource & reliability management', 'Secret exposure'), "
        "ordered by impact. Use to answer 'are these findings related' and to "
        "structure remediation. The grouping is deterministic; naming a single root "
        "cause across groups is your (AI) inference."
    )
    args_schema = _RootCauseArgs

    async def _run(self, ctx: ToolContext, args: _RootCauseArgs) -> ToolResult:  # type: ignore[override]
        from agents.investigation.correlation import group_findings

        items = await load_findings_with_paths(ctx.session, args.scan_id)
        groups = [g.to_dict() for g in group_findings(items)]
        return ToolResult(data=groups, returned=len(groups), total_available=len(groups))


class _RelatedArgs(ToolArgs):
    scan_id: uuid.UUID = Field(description="The scan the finding belongs to.")
    finding_id: uuid.UUID = Field(description="The finding to find relatives of.")
    limit: int = Field(default=DEFAULT_LIMIT, description="Max related findings (<=50).")


class GetRelatedFindingsTool(InvestigationTool):
    name = "get_related_findings"
    description = (
        "Findings deterministically related to a given finding: same file, same "
        "scanner/rule, or same category. Useful for root-cause grouping. Relation "
        "reasons are included per result."
    )
    args_schema = _RelatedArgs

    async def _run(self, ctx: ToolContext, args: _RelatedArgs) -> ToolResult:  # type: ignore[override]
        items = await load_findings_with_paths(ctx.session, args.scan_id)
        target = next((it for it in items if it[0].id == args.finding_id), None)
        if target is None:
            raise ToolError(
                f"Finding {args.finding_id} not found in scan {args.scan_id}.", code="not_found"
            )
        tf, tpath = target
        related: list[dict] = []
        for finding, path in items:
            if finding.id == args.finding_id:
                continue
            reasons = []
            if tpath and path == tpath:
                reasons.append("same_file")
            if finding.scanner == tf.scanner:
                reasons.append("same_scanner")
            if finding.rule_id == tf.rule_id:
                reasons.append("same_rule")
            if _v(finding.category) == _v(tf.category):
                reasons.append("same_category")
            if reasons:
                entry = finding_to_dict(finding, path, include_evidence=False)
                entry["relation"] = reasons
                related.append(entry)
        limit = clamp_limit(args.limit)
        return ToolResult(
            data=related[:limit],
            returned=min(len(related), limit),
            total_available=len(related),
            truncated=len(related) > limit,
        )


def _v(enum_or_str: object) -> str:
    return enum_or_str.value if hasattr(enum_or_str, "value") else str(enum_or_str)


def _validate_choice(value: str, allowed: set[str], field_name: str) -> str:
    v = value.strip().lower()
    if v not in allowed:
        raise ToolError(
            f"Invalid {field_name} '{value}'. Allowed: {sorted(allowed)}.",
            code="invalid_arguments",
        )
    return v
