"""M2 tests: AWS resource discovery + inventory sync.

Discovery functions are tested with botocore's Stubber (pagination + metadata
extraction). The sync orchestrator is tested with an injected fake discovery
(no AWS) to verify asset upsert + snapshot bookkeeping.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import boto3
import pytest
from botocore.stub import Stubber
from cryptography.fernet import Fernet

import services.cloud_discovery_service as cds
from core.config import Settings
from core.database import Database
from models.cloud import CloudAccount
from services.aws import discovery
from services.aws.resources import DiscoveredResource
from services.cloud_discovery_service import CloudDiscoveryService

FERNET_KEY = Fernet.generate_key().decode()


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'disc.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
        integration_encryption_key=FERNET_KEY,
    )


# ---- discovery functions (botocore Stubber) --------------------------------


def test_discover_ec2_instances_paginated_and_exposure() -> None:
    ec2 = boto3.client("ec2", region_name="us-east-1",
                       aws_access_key_id="x", aws_secret_access_key="y")
    stubber = Stubber(ec2)
    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {"Instances": [
                    {"InstanceId": "i-public", "PublicIpAddress": "1.2.3.4",
                     "PrivateIpAddress": "10.0.0.5", "State": {"Name": "running"},
                     "VpcId": "vpc-1", "SubnetId": "subnet-1",
                     "SecurityGroups": [{"GroupId": "sg-1"}],
                     "Tags": [{"Key": "Name", "Value": "web"},
                              {"Key": "Environment", "Value": "production"}]},
                ]},
            ],
            "NextToken": "page2",
        },
    )
    stubber.add_response(
        "describe_instances",
        {"Reservations": [
            {"Instances": [
                {"InstanceId": "i-private", "PrivateIpAddress": "10.0.0.6",
                 "State": {"Name": "running"}, "VpcId": "vpc-1"},
            ]},
        ]},
    )
    stubber.activate()

    out = discovery.discover_ec2_instances(ec2, "us-east-1")
    assert len(out) == 2  # paginated across two pages
    by_id = {r.resource_id: r for r in out}
    assert by_id["i-public"].exposure == "public"
    assert by_id["i-public"].name == "web"
    assert by_id["i-public"].tags["Environment"] == "production"
    assert by_id["i-private"].exposure == "private"


def test_discover_security_groups_normalizes_rules() -> None:
    ec2 = boto3.client("ec2", region_name="us-east-1",
                       aws_access_key_id="x", aws_secret_access_key="y")
    stubber = Stubber(ec2)
    stubber.add_response(
        "describe_security_groups",
        {"SecurityGroups": [
            {"GroupId": "sg-ssh", "GroupName": "ssh-open", "VpcId": "vpc-1",
             "IpPermissions": [
                 {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                  "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
             ],
             "IpPermissionsEgress": []},
        ]},
    )
    stubber.activate()
    out = discovery.discover_security_groups(ec2, "us-east-1")
    assert len(out) == 1
    ingress = out[0].attributes["ingress"]
    assert ingress[0]["from_port"] == 22
    assert ingress[0]["cidrs"] == ["0.0.0.0/0"]


def test_discover_s3_public_access() -> None:
    s3 = boto3.client("s3", region_name="us-east-1",
                      aws_access_key_id="x", aws_secret_access_key="y")
    stubber = Stubber(s3)
    stubber.add_response("list_buckets", {"Buckets": [{"Name": "open-bucket"}]})
    # Public access block NOT fully enabled -> not blocked.
    stubber.add_response(
        "get_public_access_block",
        {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False, "IgnorePublicAcls": False,
            "BlockPublicPolicy": False, "RestrictPublicBuckets": False}},
        {"Bucket": "open-bucket"},
    )
    stubber.add_client_error(
        "get_bucket_encryption",
        service_error_code="ServerSideEncryptionConfigurationNotFoundError",
    )
    stubber.add_response("get_bucket_versioning", {}, {"Bucket": "open-bucket"})
    stubber.add_response(
        "get_bucket_policy_status",
        {"PolicyStatus": {"IsPublic": True}}, {"Bucket": "open-bucket"},
    )
    stubber.activate()
    out = discovery.discover_s3(s3, "us-east-1")
    assert len(out) == 1
    assert out[0].resource_id == "open-bucket"
    assert out[0].exposure == "public"
    assert out[0].attributes["encryption"] is False


# ---- orchestrator (fake discovery, real DB) --------------------------------


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
        await session.commit()
    yield db, settings, pk
    await db.dispose()


_FAKE_RESOURCES = [
    DiscoveredResource(service="ec2", resource_type="instance", resource_id="i-1",
                       region="us-east-1", exposure="public", tags={"Team": "payments"}),
    DiscoveredResource(service="s3", resource_type="bucket", resource_id="data",
                       region="us-east-1", exposure="private"),
]


async def test_sync_persists_assets_and_snapshot(account, monkeypatch) -> None:
    db, settings, pk = account
    monkeypatch.setattr(cds, "build_factory", lambda s: object())
    monkeypatch.setattr(cds, "discover_all", lambda assumed, regions: list(_FAKE_RESOURCES))
    # Avoid real assume_role: the fake factory has no assume_role, so patch _discover.
    async def _fake_discover(self, acc):  # type: ignore[no-untyped-def]
        return list(_FAKE_RESOURCES)
    monkeypatch.setattr(CloudDiscoveryService, "_discover", _fake_discover)

    async with db.sessionmaker() as session:
        service = CloudDiscoveryService(session, settings)
        snapshot = await service.sync(pk)
        await session.commit()
        assert snapshot.status == "completed"
        assert snapshot.asset_count == 2
        items, total = await service.list_assets(pk)
        assert total == 2
        assert {a.resource_id for a in items} == {"i-1", "data"}


async def test_sync_upserts_without_duplicates(account, monkeypatch) -> None:
    db, settings, pk = account

    async def _fake_discover(self, acc):  # type: ignore[no-untyped-def]
        return list(_FAKE_RESOURCES)
    monkeypatch.setattr(CloudDiscoveryService, "_discover", _fake_discover)

    async with db.sessionmaker() as session:
        service = CloudDiscoveryService(session, settings)
        await service.sync(pk)
        await session.commit()
    async with db.sessionmaker() as session:
        service = CloudDiscoveryService(session, settings)
        await service.sync(pk)  # second sync - should update, not duplicate
        await session.commit()
        _, total = await service.list_assets(pk)
        assert total == 2


async def test_sync_failure_records_snapshot(account, monkeypatch) -> None:
    db, settings, pk = account

    async def _boom(self, acc):  # type: ignore[no-untyped-def]
        raise RuntimeError("assume role failed")
    monkeypatch.setattr(CloudDiscoveryService, "_discover", _boom)

    async with db.sessionmaker() as session:
        service = CloudDiscoveryService(session, settings)
        snapshot = await service.sync(pk)
        await session.commit()
        assert snapshot.status == "failed"
        assert "assume role failed" in (snapshot.error or "")
