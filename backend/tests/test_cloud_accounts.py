"""M1 tests: AWS account integration (STS AssumeRole, read-only).

Uses botocore's Stubber (ships with botocore) so no real AWS and no moto are
needed. Covers connect/validate/list/delete, invalid role ARN, access-denied,
AWS-authoritative account id, duplicate rejection, and secret non-exposure.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import boto3
import pytest
from botocore.stub import Stubber
from cryptography.fernet import Fernet

import services.cloud_account_service as cas
from core.config import Settings
from core.database import Database
from core.exceptions import CloudConnectionError, ValidationError
from services.aws.client import AWSClientFactory, validate_role_arn
from services.cloud_account_service import CloudAccountService

FERNET_KEY = Fernet.generate_key().decode()
ROLE_ARN = "arn:aws:iam::123456789012:role/DevOpsAuditorReadOnly"
ASSUMED_ARN = "arn:aws:sts::123456789012:assumed-role/DevOpsAuditorReadOnly/devops-ai-auditor"


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'cloud.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
        integration_encryption_key=FERNET_KEY,
    )


def _stubbed_factory(settings: Settings, *, deny: bool = False) -> AWSClientFactory:
    """An AWSClientFactory whose STS client is a botocore Stubber (no network)."""
    sts = boto3.client(
        "sts", region_name="us-east-1",
        aws_access_key_id="x", aws_secret_access_key="y",
    )
    stubber = Stubber(sts)
    if deny:
        stubber.add_client_error(
            "assume_role", service_error_code="AccessDenied",
            service_message="not authorized to assume role",
        )
    else:
        stubber.add_response(
            "assume_role",
            {
                "Credentials": {
                    "AccessKeyId": "ASIAEXAMPLE0123456789",
                    "SecretAccessKey": "secretKeyExampleValue000000000000000000",
                    "SessionToken": "sessionTokenExampleValue",
                    "Expiration": datetime.now(UTC),
                },
                "AssumedRoleUser": {
                    "AssumedRoleId": "AROAEXAMPLE:devops-ai-auditor",
                    "Arn": ASSUMED_ARN,
                },
            },
        )
    stubber.activate()
    return AWSClientFactory(settings, sts_client=sts)


@pytest.fixture
async def db(tmp_path: Path) -> Database:
    settings = _settings(tmp_path)
    database = Database(settings)
    await database.create_all()
    return database


# ---- validation (pure) -----------------------------------------------------


def test_validate_role_arn_accepts_valid() -> None:
    assert validate_role_arn(ROLE_ARN) == ROLE_ARN


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not-an-arn",
        "arn:aws:s3:::bucket",  # not IAM
        "arn:aws:iam::123456789012:user/alice",  # not a role
        "arn:evil:iam::123456789012:role/x",  # wrong partition
    ],
)
def test_validate_role_arn_rejects_bad(bad: str) -> None:
    with pytest.raises(ValidationError):
        validate_role_arn(bad)


# ---- connect ---------------------------------------------------------------


async def test_connect_uses_aws_verified_account_id(db: Database, monkeypatch) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    monkeypatch.setattr(cas, "build_factory", lambda s: _stubbed_factory(s))
    async with db.sessionmaker() as session:
        service = CloudAccountService(session, settings)
        # Note: NO account id is supplied by the caller - it comes from AWS.
        account = await service.connect(
            name="prod", role_arn=ROLE_ARN, external_id="secret-ext-id",
            regions=["us-east-1", "ap-south-1"],
        )
        assert account.account_id == "123456789012"
        assert account.status == "connected"
        assert account.regions == ["us-east-1", "ap-south-1"]
        # External id stored encrypted, never plaintext.
        assert account.encrypted_external_id
        assert "secret-ext-id" not in account.encrypted_external_id


async def test_connect_rejects_invalid_role_arn(db: Database) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    async with db.sessionmaker() as session:
        with pytest.raises(ValidationError):
            await CloudAccountService(session, settings).connect(
                name="x", role_arn="not-an-arn", external_id=None, regions=["us-east-1"]
            )


async def test_connect_rejects_bad_region(db: Database) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    async with db.sessionmaker() as session:
        with pytest.raises(ValidationError):
            await CloudAccountService(session, settings).connect(
                name="x", role_arn=ROLE_ARN, external_id=None, regions=["mars-1"]
            )


async def test_connect_access_denied_raises_cloud_error(db: Database, monkeypatch) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    monkeypatch.setattr(cas, "build_factory", lambda s: _stubbed_factory(s, deny=True))
    async with db.sessionmaker() as session:
        with pytest.raises(CloudConnectionError):
            await CloudAccountService(session, settings).connect(
                name="x", role_arn=ROLE_ARN, external_id="wrong", regions=["us-east-1"]
            )


async def test_duplicate_account_rejected(db: Database, monkeypatch) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    monkeypatch.setattr(cas, "build_factory", lambda s: _stubbed_factory(s))
    async with db.sessionmaker() as session:
        service = CloudAccountService(session, settings)
        await service.connect(name="a", role_arn=ROLE_ARN, external_id=None, regions=["us-east-1"])
        await session.commit()
    async with db.sessionmaker() as session:
        service = CloudAccountService(session, settings)
        with pytest.raises(ValidationError):
            await service.connect(
                name="b", role_arn=ROLE_ARN, external_id=None, regions=["us-east-1"]
            )


async def test_list_get_delete(db: Database, monkeypatch) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    monkeypatch.setattr(cas, "build_factory", lambda s: _stubbed_factory(s))
    async with db.sessionmaker() as session:
        service = CloudAccountService(session, settings)
        account = await service.connect(
            name="prod", role_arn=ROLE_ARN, external_id=None, regions=["us-east-1"]
        )
        await session.commit()
        pk = account.id

    async with db.sessionmaker() as session:
        service = CloudAccountService(session, settings)
        assert len(await service.list_accounts()) == 1
        got = await service.get(pk)
        assert got.account_id == "123456789012"
        await service.delete(pk)
        await session.commit()

    async with db.sessionmaker() as session:
        service = CloudAccountService(session, settings)
        assert len(await service.list_accounts()) == 0
