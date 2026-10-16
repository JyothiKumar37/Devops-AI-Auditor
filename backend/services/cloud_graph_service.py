"""Network exposure graph + attack surface (Phase 4).

Builds a directed relationship graph from discovered assets using ONLY evidence
present in the metadata (route tables -> IGW, instance -> subnet/SG, public IPs,
internet-facing LBs, publicly-accessible RDS, public EKS endpoints). No
relationship is invented. The graph powers the UI and the AI network
investigation; the attack surface summarises genuinely internet-reachable assets.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.exceptions import NotFoundError
from models.cloud import CloudAccount, CloudAsset, CloudFinding, CloudRelationship
from models.enums import Severity

INTERNET = "internet"

# Default exposure severity by service when a resource carries no finding.
_EXPOSURE_SEVERITY = {
    "rds": "critical",   # internet-facing database
    "eks": "high",
    "ec2": "high",
    "s3": "high",
    "elb": "medium",     # internet-facing LB is often expected
}


class CloudGraphService:
    """Derives, persists and serves the cloud network graph."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    async def _account(self, account_pk: uuid.UUID) -> CloudAccount:
        account = await self._session.get(CloudAccount, account_pk)
        if account is None:
            raise NotFoundError(f"Cloud account {account_pk} not found.")
        return account

    async def _assets(self, account_pk: uuid.UUID) -> list[CloudAsset]:
        return list(
            (
                await self._session.scalars(
                    select(CloudAsset).where(CloudAsset.account_id == account_pk)
                )
            ).all()
        )

    async def rebuild(self, account_pk: uuid.UUID) -> int:
        """Recompute and persist the account's relationship edges."""
        assets = await self._assets(account_pk)
        edges = _derive_edges(assets)
        await self._session.execute(
            delete(CloudRelationship).where(CloudRelationship.account_id == account_pk)
        )
        for src, tgt, rel, detail in edges:
            self._session.add(
                CloudRelationship(
                    id=uuid.uuid4(), account_id=account_pk,
                    source_resource_id=src, target_resource_id=tgt,
                    relation=rel, detail=detail,
                )
            )
        await self._session.flush()
        return len(edges)

    async def network_graph(self, account_pk: uuid.UUID) -> dict[str, Any]:
        await self._account(account_pk)
        assets = await self._assets(account_pk)
        edges = _derive_edges(assets)
        severities = await self._finding_severity_by_resource(account_pk)

        referenced: set[str] = {INTERNET}
        for src, tgt, _rel, _d in edges:
            referenced.add(src)
            referenced.add(tgt)

        nodes: list[dict[str, Any]] = [
            {"id": INTERNET, "type": "internet", "service": "internet", "label": "Internet"}
        ]
        for a in assets:
            if a.resource_id in referenced or a.exposure == "public":
                nodes.append(
                    {
                        "id": a.resource_id,
                        "type": a.resource_type,
                        "service": a.service,
                        "label": a.name or a.resource_id,
                        "region": a.region,
                        "exposure": a.exposure,
                        "max_severity": severities.get(a.resource_id),
                    }
                )
        return {
            "account_id": str(account_pk),
            "nodes": nodes[:500],
            "edges": [
                {"source": s, "target": t, "relation": r, "detail": d}
                for (s, t, r, d) in edges
            ][:1000],
        }

    async def attack_surface(self, account_pk: uuid.UUID) -> dict[str, Any]:
        await self._account(account_pk)
        assets = await self._assets(account_pk)
        severities = await self._finding_severity_by_resource(account_pk)

        public = [a for a in assets if a.exposure == "public"]
        resources: list[dict[str, Any]] = []
        by_severity: dict[str, int] = {s.value: 0 for s in Severity}
        by_service: dict[str, int] = {}
        for a in public:
            sev = severities.get(a.resource_id) or _EXPOSURE_SEVERITY.get(a.service, "medium")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_service[a.service] = by_service.get(a.service, 0) + 1
            resources.append(
                {
                    "resource_id": a.resource_id, "service": a.service,
                    "region": a.region, "name": a.name, "severity": sev,
                }
            )
        resources.sort(key=lambda r: -Severity(r["severity"]).rank)
        return {
            "account_id": str(account_pk),
            "internet_facing": len(public),
            "by_severity": by_severity,
            "by_service": by_service,
            "resources": resources,
        }

    async def relationships_for(
        self, account_pk: uuid.UUID, resource_id: str
    ) -> list[dict[str, Any]]:
        rows = (
            await self._session.scalars(
                select(CloudRelationship).where(
                    CloudRelationship.account_id == account_pk,
                    (CloudRelationship.source_resource_id == resource_id)
                    | (CloudRelationship.target_resource_id == resource_id),
                )
            )
        ).all()
        return [
            {
                "source": r.source_resource_id, "target": r.target_resource_id,
                "relation": r.relation, "detail": r.detail,
            }
            for r in rows
        ]

    async def _finding_severity_by_resource(self, account_pk: uuid.UUID) -> dict[str, str]:
        rows = (
            await self._session.scalars(
                select(CloudFinding).where(CloudFinding.account_id == account_pk)
            )
        ).all()
        out: dict[str, str] = {}
        for f in rows:
            cur = out.get(f.resource_id)
            if cur is None or Severity(f.severity).rank > Severity(cur).rank:
                out[f.resource_id] = f.severity
        return out


def _derive_edges(assets: list[CloudAsset]) -> list[tuple[str, str, str, dict]]:
    """Derive evidence-backed directed edges from discovered assets."""
    edges: list[tuple[str, str, str, dict]] = []

    # Public subnets: those whose route table routes to an internet gateway.
    public_subnets: set[str] = set()
    for a in assets:
        if a.service == "vpc" and a.resource_type == "route-table":
            routes = a.attributes.get("routes", [])
            igws = [
                r.get("gateway_id") for r in routes
                if str(r.get("gateway_id", "")).startswith("igw-")
            ]
            if igws:
                for subnet_id in a.attributes.get("subnets", []):
                    public_subnets.add(subnet_id)
                    edges.append((igws[0], subnet_id, "routes-to", {"via": "route-table"}))

    for a in assets:
        rid, attrs = a.resource_id, a.attributes
        if a.service == "vpc" and a.resource_type == "internet-gateway":
            edges.append((INTERNET, rid, "exposes", {}))
            for vpc_id in attrs.get("vpc_ids", []):
                edges.append((rid, vpc_id, "attached-to", {}))
        elif a.service == "vpc" and a.resource_type == "subnet":
            if attrs.get("vpc_id"):
                edges.append((rid, attrs["vpc_id"], "attached-to", {}))
        elif a.service == "ec2" and a.resource_type == "instance":
            if attrs.get("subnet_id"):
                edges.append((attrs["subnet_id"], rid, "contains", {}))
            for sg in attrs.get("security_groups", []):
                edges.append((rid, sg, "uses", {}))
            if attrs.get("public_ip"):
                edges.append((INTERNET, rid, "exposes", {"public_ip": attrs["public_ip"]}))
        elif a.service == "elb" and a.resource_type == "load-balancer":
            if attrs.get("scheme") == "internet-facing":
                edges.append((INTERNET, rid, "exposes", {"scheme": "internet-facing"}))
            if attrs.get("vpc_id"):
                edges.append((rid, attrs["vpc_id"], "attached-to", {}))
        elif a.service == "rds" and a.resource_type == "db-instance":
            if attrs.get("publicly_accessible"):
                edges.append((INTERNET, rid, "exposes", {"publicly_accessible": True}))
            for sg in attrs.get("vpc_security_groups", []):
                edges.append((rid, sg, "uses", {}))
        elif a.service == "eks" and a.resource_type == "cluster":
            if attrs.get("endpoint_public_access"):
                edges.append((INTERNET, rid, "exposes", {"endpoint": "public"}))
    return edges
