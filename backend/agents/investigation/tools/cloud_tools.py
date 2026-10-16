"""Controlled, read-only cloud investigation tools (Phase 4).

Expose cloud accounts/assets/findings/posture/network/drift/compliance to the AI
agent through the same validated, bounded, secret-redacted tool contract as the
rest of the investigation layer. These tools return METADATA only - never AWS
access keys, session tokens, SSM/Secrets Manager values, or the account's
external id. Account scope is enforced via ``ctx.authorizes_account``.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import Field
from sqlalchemy import select

from agents.investigation.redaction import redact_secrets
from agents.investigation.tools.base import (
    InvestigationTool,
    ToolArgs,
    ToolContext,
    ToolError,
    ToolResult,
    clamp_limit,
)
from agents.reasoning.sanitize import neutralize
from models.cloud import CloudAccount, CloudAsset, CloudDrift, CloudFinding
from models.enums import Severity


def _redact(value: Any) -> Any:
    """Recursively redact any secret-looking strings in cloud metadata (defence in depth)."""
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


class _AccountArgs(ToolArgs):
    account_id: uuid.UUID = Field(description="The cloud account to inspect.")


class ListCloudAccountsTool(InvestigationTool):
    name = "list_cloud_accounts"
    description = "List connected cloud accounts (ids, provider, status). No secrets."

    async def _run(self, ctx: ToolContext, args: ToolArgs) -> ToolResult:
        rows = (await ctx.session.scalars(select(CloudAccount))).all()
        data = [
            {
                "account_pk": str(a.id), "provider": a.provider, "name": a.name,
                "account_id": a.account_id, "status": a.status,
                "regions": a.regions, "last_synced_at": str(a.last_synced_at or ""),
            }
            for a in rows
            if ctx.authorizes_account(a.id)
        ]
        return ToolResult(data=data, returned=len(data))


class _AssetsArgs(_AccountArgs):
    service: str | None = Field(default=None, description="Filter by service, e.g. ec2.")
    exposure: str | None = Field(default=None, description="Filter: public|private|none|unknown.")
    limit: int = Field(default=50)


class GetCloudAssetsTool(InvestigationTool):
    name = "get_cloud_assets"
    description = (
        "List discovered AWS resources for an account (metadata only), optionally "
        "filtered by service (ec2|vpc|s3|rds|iam|eks|elb|...) or exposure."
    )
    args_schema = _AssetsArgs

    async def _run(self, ctx: ToolContext, args: _AssetsArgs) -> ToolResult:  # type: ignore[override]
        query = select(CloudAsset).where(CloudAsset.account_id == args.account_id)
        if args.service:
            query = query.where(CloudAsset.service == args.service)
        if args.exposure:
            query = query.where(CloudAsset.exposure == args.exposure)
        rows = list((await ctx.session.scalars(query)).all())
        total = len(rows)
        limit = clamp_limit(args.limit)
        data = [
            {
                "resource_id": a.resource_id, "service": a.service,
                "resource_type": a.resource_type, "region": a.region,
                "exposure": a.exposure, "name": neutralize(a.name, max_length=200),
                "tags": _redact(a.tags),
            }
            for a in rows[:limit]
        ]
        return ToolResult(data=data, returned=len(data), total_available=total,
                          truncated=total > limit)


class _ResourceArgs(_AccountArgs):
    resource_id: str = Field(description="The resource id (e.g. i-123, sg-abc, bucket name).")


class GetCloudResourceTool(InvestigationTool):
    name = "get_cloud_resource"
    description = "Full metadata for one cloud resource (secret-redacted)."
    args_schema = _ResourceArgs

    async def _run(self, ctx: ToolContext, args: _ResourceArgs) -> ToolResult:  # type: ignore[override]
        asset = await ctx.session.scalar(
            select(CloudAsset).where(
                CloudAsset.account_id == args.account_id,
                CloudAsset.resource_id == args.resource_id,
            )
        )
        if asset is None:
            raise ToolError(f"Resource {args.resource_id} not found.", code="not_found")
        return ToolResult(
            data={
                "resource_id": asset.resource_id, "service": asset.service,
                "resource_type": asset.resource_type, "region": asset.region,
                "arn": asset.arn, "exposure": asset.exposure, "state": asset.state,
                "tags": _redact(asset.tags), "attributes": _redact(asset.attributes),
            },
            returned=1,
        )


class _FindingsArgs(_AccountArgs):
    severity: str | None = Field(default=None, description="Filter: critical|high|medium|low")
    limit: int = Field(default=50)


class GetCloudFindingsTool(InvestigationTool):
    name = "get_cloud_findings"
    description = "Deterministic cloud security findings for an account (severity-sorted)."
    args_schema = _FindingsArgs

    async def _run(self, ctx: ToolContext, args: _FindingsArgs) -> ToolResult:  # type: ignore[override]
        query = select(CloudFinding).where(CloudFinding.account_id == args.account_id)
        if args.severity:
            query = query.where(CloudFinding.severity == args.severity)
        rows = list((await ctx.session.scalars(query)).all())
        rows.sort(key=lambda f: -Severity(f.severity).rank)
        total = len(rows)
        limit = clamp_limit(args.limit)
        data = [
            {
                "rule_id": f.rule_id, "service": f.service, "resource_id": f.resource_id,
                "severity": f.severity, "title": neutralize(f.title, max_length=200),
                "evidence": neutralize(redact_secrets(f.evidence or ""), max_length=300),
                "recommendation": neutralize(f.recommendation, max_length=300),
                "compliance": f.compliance,
            }
            for f in rows[:limit]
        ]
        return ToolResult(data=data, returned=len(data), total_available=total,
                          truncated=total > limit)


class GetCloudPostureTool(InvestigationTool):
    name = "get_cloud_posture"
    description = "Deterministic cloud posture (cloud/network/iam domain scores)."
    args_schema = _AccountArgs

    async def _run(self, ctx: ToolContext, args: _AccountArgs) -> ToolResult:  # type: ignore[override]
        from services.cloud_posture_service import CloudPostureService

        posture = await CloudPostureService(ctx.session, ctx.settings).posture(args.account_id)
        return ToolResult(data=posture, returned=1)


class GetNetworkGraphTool(InvestigationTool):
    name = "get_network_graph"
    description = "Network exposure graph (nodes + evidence-backed edges) for an account."
    args_schema = _AccountArgs

    async def _run(self, ctx: ToolContext, args: _AccountArgs) -> ToolResult:  # type: ignore[override]
        from services.cloud_graph_service import CloudGraphService

        graph = await CloudGraphService(ctx.session, ctx.settings).network_graph(args.account_id)
        return ToolResult(data=graph, returned=len(graph.get("nodes", [])))


class GetIamAnalysisTool(InvestigationTool):
    name = "get_iam_analysis"
    description = "IAM findings + user/role summary for an account (no secret values)."
    args_schema = _AccountArgs

    async def _run(self, ctx: ToolContext, args: _AccountArgs) -> ToolResult:  # type: ignore[override]
        assets = list(
            (
                await ctx.session.scalars(
                    select(CloudAsset).where(
                        CloudAsset.account_id == args.account_id, CloudAsset.service == "iam"
                    )
                )
            ).all()
        )
        findings = list(
            (
                await ctx.session.scalars(
                    select(CloudFinding).where(
                        CloudFinding.account_id == args.account_id,
                        CloudFinding.service == "iam",
                    )
                )
            ).all()
        )
        return ToolResult(
            data={
                "users": sum(1 for a in assets if a.resource_type == "user"),
                "roles": sum(1 for a in assets if a.resource_type == "role"),
                "findings": [
                    {"rule_id": f.rule_id, "resource_id": f.resource_id,
                     "severity": f.severity, "title": neutralize(f.title, max_length=200)}
                    for f in findings
                ],
            },
            returned=len(findings),
        )


class GetDriftTool(InvestigationTool):
    name = "get_drift"
    description = "Terraform-vs-AWS drift records for an account (IN_SYNC/DRIFTED/...)."
    args_schema = _AccountArgs

    async def _run(self, ctx: ToolContext, args: _AccountArgs) -> ToolResult:  # type: ignore[override]
        rows = list(
            (
                await ctx.session.scalars(
                    select(CloudDrift).where(CloudDrift.account_id == args.account_id)
                )
            ).all()
        )
        data = [
            {
                "resource_id": d.resource_id, "service": d.service,
                "terraform_address": d.terraform_address, "status": d.status,
                "differences": _redact(d.differences),
            }
            for d in rows
        ]
        return ToolResult(data=data, returned=len(data))


class _ComplianceArgs(_AccountArgs):
    framework: str = Field(default="CIS_AWS", description="Framework key, e.g. CIS_AWS.")


class GetComplianceStatusTool(InvestigationTool):
    name = "get_compliance_status"
    description = "Compliance assessment (PASS/FAIL/...) for an account + framework."
    args_schema = _ComplianceArgs

    async def _run(self, ctx: ToolContext, args: _ComplianceArgs) -> ToolResult:  # type: ignore[override]
        from services.compliance_service import ComplianceService

        assessment = await ComplianceService(ctx.session, ctx.settings).assess(
            args.account_id, args.framework
        )
        return ToolResult(data=assessment, returned=len(assessment.get("controls", [])))
