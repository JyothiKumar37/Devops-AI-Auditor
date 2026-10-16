"""M6 tests: EKS <-> Kubernetes correlation (best-effort, evidence-backed)."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from core.config import Settings
from core.database import Database
from models.cloud import CloudAccount, CloudAsset
from models.scan import Scan
from services.cloud_kubernetes_service import CloudKubernetesService


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'eks.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )


@pytest.fixture
async def env(tmp_path: Path):
    settings = _settings(tmp_path)
    db = Database(settings)
    await db.create_all()
    acct = uuid.uuid4()
    scan_id = uuid.uuid4()
    async with db.sessionmaker() as session:
        session.add(CloudAccount(
            id=acct, provider="aws", name="prod", account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/RO", regions=["us-east-1"],
            status="connected",
        ))
        session.add(CloudAsset(
            id=uuid.uuid4(), account_id=acct, service="eks", resource_type="cluster",
            resource_id="prod-cluster", region="us-east-1", exposure="public",
            attributes={"endpoint_public_access": True},
        ))
        session.add(Scan(
            id=scan_id, repository_name="acme/infra", source_type="zip", status="completed",
            correlation_index={
                "eks_clusters": [{"file": "eks.tf", "name": "prod-cluster"}],
                "k8s_services": [{"file": "svc.yaml", "name": "web", "namespace": "default"}],
                "k8s_workloads": [{"name": "web", "namespace": "default"}],
            },
        ))
        await session.commit()
    yield db, settings, acct, scan_id
    await db.dispose()


async def test_correlation_links_tf_eks_k8s(env) -> None:
    db, settings, acct, scan_id = env
    async with db.sessionmaker() as session:
        result = await CloudKubernetesService(session, settings).correlate(acct, scan_id)
    assert result["clusters"] == 1
    corr = result["correlations"][0]
    assert corr["cluster"] == "prod-cluster"
    assert corr["terraform_managed"] is True
    assert corr["endpoint_public_access"] is True
    assert corr["kubernetes"]["has_scan_evidence"] is True
    layers = [p["layer"] for p in corr["path"]]
    assert layers[0] == "terraform" and "aws-eks" in layers and layers[-1] == "internet"


async def test_correlation_degrades_without_scan(env) -> None:
    db, settings, acct, _ = env
    async with db.sessionmaker() as session:
        result = await CloudKubernetesService(session, settings).correlate(acct, None)
    corr = result["correlations"][0]
    # Still reports the cluster + AWS/internet linkage, just no k8s evidence.
    assert corr["terraform_managed"] is False
    assert corr["kubernetes"]["has_scan_evidence"] is False
    assert any(p["layer"] == "aws-eks" for p in corr["path"])
