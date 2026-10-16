"""M4 tests: network exposure graph + attack surface (evidence-backed edges)."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from core.config import Settings
from core.database import Database
from models.cloud import CloudAccount, CloudAsset, CloudFinding
from services.cloud_graph_service import INTERNET, CloudGraphService, _derive_edges


def _asset(service, rtype, rid, **attrs) -> CloudAsset:
    return CloudAsset(
        id=uuid.uuid4(), account_id=uuid.uuid4(), service=service, resource_type=rtype,
        resource_id=rid, region="us-east-1", exposure=attrs.pop("exposure", "unknown"),
        attributes=attrs,
    )


def test_derive_edges_public_path() -> None:
    assets = [
        _asset("vpc", "internet-gateway", "igw-1", vpc_ids=["vpc-1"]),
        _asset("vpc", "route-table", "rtb-1",
               routes=[{"destination": "0.0.0.0/0", "gateway_id": "igw-1"}],
               subnets=["subnet-pub"]),
        _asset("vpc", "subnet", "subnet-pub", vpc_id="vpc-1"),
        _asset("ec2", "instance", "i-1", exposure="public",
               public_ip="1.2.3.4", subnet_id="subnet-pub", security_groups=["sg-1"]),
        _asset("rds", "db-instance", "db-1", exposure="public",
               publicly_accessible=True, vpc_security_groups=["sg-db"]),
    ]
    edges = _derive_edges(assets)
    # internet -> igw, igw -> subnet (public via route), internet -> instance, internet -> rds
    assert (INTERNET, "igw-1", "exposes", {}) in edges
    assert any(s == "igw-1" and t == "subnet-pub" and r == "routes-to" for s, t, r, _ in edges)
    assert any(s == INTERNET and t == "i-1" and r == "exposes" for s, t, r, _ in edges)
    assert any(s == INTERNET and t == "db-1" and r == "exposes" for s, t, r, _ in edges)
    # instance uses its security group
    assert any(s == "i-1" and t == "sg-1" and r == "uses" for s, t, r, _ in edges)


def test_no_invented_edges_for_private_instance() -> None:
    assets = [
        _asset("ec2", "instance", "i-priv", exposure="private",
               subnet_id="subnet-x", security_groups=["sg-1"]),
    ]
    edges = _derive_edges(assets)
    assert not any(s == INTERNET for s, _t, _r, _d in edges)  # no internet exposure edge


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'graph.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )


@pytest.fixture
async def account(tmp_path: Path):
    settings = _settings(tmp_path)
    db = Database(settings)
    await db.create_all()
    pk = uuid.uuid4()
    async with db.sessionmaker() as session:
        session.add(CloudAccount(
            id=pk, provider="aws", name="prod", account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/RO", regions=["us-east-1"],
            status="connected",
        ))
        session.add(CloudAsset(
            id=uuid.uuid4(), account_id=pk, service="rds", resource_type="db-instance",
            resource_id="db-1", region="us-east-1", exposure="public",
            attributes={"publicly_accessible": True},
        ))
        session.add(CloudAsset(
            id=uuid.uuid4(), account_id=pk, service="elb", resource_type="load-balancer",
            resource_id="alb-1", region="us-east-1", exposure="public",
            attributes={"scheme": "internet-facing"},
        ))
        session.add(CloudFinding(
            id=uuid.uuid4(), account_id=pk, service="rds", resource_id="db-1",
            region="us-east-1", rule_id="AWS-RDS-001", scanner="aws-rds",
            category="security", severity="critical", confidence="high",
            title="public db", fingerprint="AWS-RDS-001|db-1|x",
        ))
        await session.commit()
    yield db, settings, pk
    await db.dispose()


async def test_attack_surface_counts(account) -> None:
    db, settings, pk = account
    async with db.sessionmaker() as session:
        surface = await CloudGraphService(session, settings).attack_surface(pk)
    assert surface["internet_facing"] == 2  # rds + alb
    # RDS uses its finding severity (critical); ALB defaults to medium (expected).
    assert surface["by_severity"]["critical"] == 1
    assert surface["by_severity"]["medium"] == 1
    assert surface["resources"][0]["service"] == "rds"  # critical sorted first


async def test_network_graph_has_internet_node_and_edges(account) -> None:
    db, settings, pk = account
    async with db.sessionmaker() as session:
        graph = await CloudGraphService(session, settings).network_graph(pk)
    node_ids = {n["id"] for n in graph["nodes"]}
    assert INTERNET in node_ids and "db-1" in node_ids
    assert any(e["source"] == INTERNET and e["target"] == "db-1" for e in graph["edges"])


async def test_rebuild_persists_relationships(account) -> None:
    db, settings, pk = account
    async with db.sessionmaker() as session:
        service = CloudGraphService(session, settings)
        n = await service.rebuild(pk)
        await session.commit()
        assert n >= 1
        rels = await service.relationships_for(pk, "db-1")
        assert any(r["source"] == INTERNET and r["target"] == "db-1" for r in rels)
