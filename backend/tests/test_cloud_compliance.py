"""M7 tests: compliance assessment + exceptions (PASS/FAIL/NOT_ASSESSED/NOT_APPLICABLE/expiry)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from core.config import Settings
from core.database import Database
from models.cloud import CloudAccount, CloudAsset, CloudFinding
from services.compliance_service import (
    FAIL,
    NOT_APPLICABLE,
    NOT_ASSESSED,
    PASS,
    ComplianceService,
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'comp.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )


async def _seed(db, *, synced: bool, with_finding: bool) -> uuid.UUID:
    acct = uuid.uuid4()
    async with db.sessionmaker() as session:
        session.add(CloudAccount(
            id=acct, provider="aws", name="prod", account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/RO", regions=["us-east-1"],
            status="connected",
            last_synced_at=datetime.now(UTC) if synced else None,
        ))
        # An EC2 security group asset makes CIS-4.1/5.2 applicable.
        session.add(CloudAsset(
            id=uuid.uuid4(), account_id=acct, service="ec2", resource_type="security-group",
            resource_id="sg-1", region="us-east-1", attributes={},
        ))
        if with_finding:
            session.add(CloudFinding(
                id=uuid.uuid4(), account_id=acct, service="ec2", resource_id="sg-1",
                region="us-east-1", rule_id="AWS-SG-001", scanner="aws-ec2",
                category="security", severity="high", confidence="high",
                title="ssh open", fingerprint="AWS-SG-001|sg-1|x",
            ))
        await session.commit()
    return acct


@pytest.fixture
async def db(tmp_path: Path):
    database = Database(_settings(tmp_path))
    await database.create_all()
    yield database
    await database.dispose()


def _control(assessment: dict, control_id: str) -> dict:
    return next(c for c in assessment["controls"] if c["control_id"] == control_id)


async def test_control_fails_with_finding(db) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    acct = await _seed(db, synced=True, with_finding=True)
    async with db.sessionmaker() as session:
        assessment = await ComplianceService(session, settings).assess(acct, "CIS_AWS")
    assert _control(assessment, "CIS-4.1")["status"] == FAIL
    assert assessment["summary"][FAIL] >= 1
    assert "not a certification" in assessment["disclaimer"].lower()


async def test_control_passes_without_finding(db) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    acct = await _seed(db, synced=True, with_finding=False)
    async with db.sessionmaker() as session:
        assessment = await ComplianceService(session, settings).assess(acct, "CIS_AWS")
    assert _control(assessment, "CIS-4.1")["status"] == PASS


async def test_not_applicable_when_service_absent(db) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    acct = await _seed(db, synced=True, with_finding=False)
    async with db.sessionmaker() as session:
        assessment = await ComplianceService(session, settings).assess(acct, "CIS_AWS")
    # No RDS assets -> RDS controls are NOT_APPLICABLE.
    assert _control(assessment, "CIS-2.3.3")["status"] == NOT_APPLICABLE


async def test_not_assessed_before_sync(db) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    acct = await _seed(db, synced=False, with_finding=False)
    async with db.sessionmaker() as session:
        assessment = await ComplianceService(session, settings).assess(acct, "CIS_AWS")
    assert all(c["status"] == NOT_ASSESSED for c in assessment["controls"])


async def test_active_exception_turns_fail_into_pass(db) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    acct = await _seed(db, synced=True, with_finding=True)
    async with db.sessionmaker() as session:
        service = ComplianceService(session, settings)
        await service.create_exception(
            acct, framework="CIS_AWS", control_id="CIS-4.1",
            reason="accept_risk", owner="sec-team",
            expires_at=datetime.now(UTC) + timedelta(days=30),
        )
        await session.commit()
        assessment = await service.assess(acct, "CIS_AWS")
    assert _control(assessment, "CIS-4.1")["status"] == PASS  # excepted


async def test_expired_exception_does_not_apply(db) -> None:
    settings = _settings(Path(db._settings.workspace_root).parent)  # noqa: SLF001
    acct = await _seed(db, synced=True, with_finding=True)
    async with db.sessionmaker() as session:
        service = ComplianceService(session, settings)
        await service.create_exception(
            acct, framework="CIS_AWS", control_id="CIS-4.1",
            reason="accept_risk", owner="sec-team",
            expires_at=datetime.now(UTC) - timedelta(days=1),  # already expired
        )
        await session.commit()
        assessment = await service.assess(acct, "CIS_AWS")
    assert _control(assessment, "CIS-4.1")["status"] == FAIL  # expired -> still fails
