"""EKS <-> Kubernetes correlation (Phase 4, best-effort, evidence-backed).

Links live AWS EKS clusters to Terraform-declared clusters and to the Kubernetes
workloads/services discovered in a repository scan (via the existing
``Scan.correlation_index``). Produces an end-to-end path:

    Terraform -> AWS EKS -> Kubernetes workloads -> Services -> (Load Balancer) -> Internet

Degrades gracefully: if there is no Kubernetes scan data the correlation still
reports the cluster and its Terraform/AWS linkage.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.exceptions import NotFoundError
from models.cloud import CloudAccount, CloudAsset
from models.scan import Scan


class CloudKubernetesService:
    """Correlate EKS clusters with Terraform and Kubernetes repository evidence."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    async def correlate(
        self, account_pk: uuid.UUID, scan_id: uuid.UUID | None = None
    ) -> dict[str, Any]:
        account = await self._session.get(CloudAccount, account_pk)
        if account is None:
            raise NotFoundError(f"Cloud account {account_pk} not found.")

        clusters = list(
            (
                await self._session.scalars(
                    select(CloudAsset).where(
                        CloudAsset.account_id == account_pk, CloudAsset.service == "eks"
                    )
                )
            ).all()
        )

        index: dict[str, Any] = {}
        if scan_id is not None:
            scan = await self._session.get(Scan, scan_id)
            if scan is None:
                raise NotFoundError(f"Scan {scan_id} not found.")
            index = getattr(scan, "correlation_index", None) or {}

        tf_cluster_names = {c.get("name") for c in index.get("eks_clusters", [])}
        k8s_services = index.get("k8s_services", [])
        k8s_workloads = index.get("k8s_workloads", [])

        correlations: list[dict[str, Any]] = []
        for cluster in clusters:
            tf_managed = cluster.resource_id in tf_cluster_names
            public = bool(cluster.attributes.get("endpoint_public_access"))
            path: list[dict[str, Any]] = []
            if tf_managed:
                path.append({"layer": "terraform", "ref": f"aws_eks_cluster.{cluster.resource_id}"})
            path.append({"layer": "aws-eks", "ref": cluster.resource_id})
            if k8s_workloads:
                path.append({"layer": "kubernetes-workloads", "count": len(k8s_workloads)})
            if k8s_services:
                path.append({"layer": "kubernetes-services", "count": len(k8s_services)})
            if public:
                path.append({"layer": "internet", "ref": "public endpoint"})
            correlations.append(
                {
                    "cluster": cluster.resource_id,
                    "region": cluster.region,
                    "terraform_managed": tf_managed,
                    "endpoint_public_access": public,
                    "kubernetes": {
                        "has_scan_evidence": bool(scan_id and (k8s_services or k8s_workloads)),
                        "workloads": len(k8s_workloads),
                        "services": [
                            {"name": s.get("name"), "namespace": s.get("namespace")}
                            for s in k8s_services
                        ][:50],
                    },
                    "path": path,
                }
            )

        return {
            "account_id": str(account_pk),
            "scan_id": str(scan_id) if scan_id else None,
            "clusters": len(clusters),
            "correlations": correlations,
        }
