"""Cloud security posture + findings queries (Phase 4).

Reuses the Phase 1 deterministic scoring engine (``services.posture``) over cloud
findings, surfacing the cloud/network/iam domains. Cloud posture is account-scoped
(a cloud account is a distinct subject from a repository scan), so it never
perturbs repository posture.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.exceptions import NotFoundError
from models.cloud import CloudAccount, CloudFinding
from models.enums import Severity
from services.posture import CLOUD_DOMAINS, assess_posture


class CloudPostureService:
    """Compute cloud posture and list cloud findings for an account."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    async def _account(self, account_pk: uuid.UUID) -> CloudAccount:
        account = await self._session.get(CloudAccount, account_pk)
        if account is None:
            raise NotFoundError(f"Cloud account {account_pk} not found.")
        return account

    async def list_findings(
        self,
        account_pk: uuid.UUID,
        *,
        service: str | None = None,
        severity: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> tuple[list[CloudFinding], int]:
        await self._account(account_pk)
        query = select(CloudFinding).where(CloudFinding.account_id == account_pk)
        if service:
            query = query.where(CloudFinding.service == service)
        if severity:
            query = query.where(CloudFinding.severity == severity)
        rows = list((await self._session.scalars(query)).all())
        rows.sort(key=lambda f: -Severity(f.severity).rank)
        total = len(rows)
        page = rows[offset : offset + min(max(limit, 1), 500)]
        return page, total

    async def posture(self, account_pk: uuid.UUID) -> dict[str, Any]:
        await self._account(account_pk)
        findings = list(
            (
                await self._session.scalars(
                    select(CloudFinding).where(CloudFinding.account_id == account_pk)
                )
            ).all()
        )
        finding_dicts = [
            {
                "scanner": f.scanner,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "rule_id": f.rule_id,
                "title": f.title,
                "recommendation": f.recommendation,
                "file": f.resource_id,
            }
            for f in findings
        ]
        domains = assess_posture(finding_dicts, files=[])
        cloud_domains = [d for d in domains if d.key in CLOUD_DOMAINS]
        applicable = [d for d in cloud_domains if d.applicable]
        overall = (
            round(sum(d.score for d in applicable) / len(applicable)) if applicable else 100
        )

        severity_counts = {s.value: 0 for s in Severity}
        by_service: dict[str, int] = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            by_service[f.service] = by_service.get(f.service, 0) + 1

        return {
            "account_id": str(account_pk),
            "overall": overall,
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "by_service": by_service,
            "domains": [
                {
                    "key": d.key, "label": d.label, "score": d.score,
                    "applicable": d.applicable, "findings": d.findings,
                    "counts": d.counts, "explanation": d.explanation,
                }
                for d in cloud_domains
            ],
            "top_risk_areas": [
                {"key": d.key, "label": d.label, "score": d.score}
                for d in sorted(applicable, key=lambda d: d.score)
                if d.score < 100
            ][:3],
        }
