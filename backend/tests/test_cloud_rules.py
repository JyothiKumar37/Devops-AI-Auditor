"""M3 tests: deterministic cloud security rules + posture (context-aware)."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from core.config import Settings
from core.database import Database
from models.cloud import CloudAccount, CloudFinding
from models.enums import Severity
from services.aws.resources import DiscoveredResource
from services.aws.rules import all_rules, evaluate_asset
from services.cloud_posture_service import CloudPostureService


def _run(asset: DiscoveredResource) -> list:
    return evaluate_asset(asset, all_rules())


def _sg(ingress: list[dict]) -> DiscoveredResource:
    return DiscoveredResource(
        service="ec2", resource_type="security-group", resource_id="sg-1",
        region="us-east-1", attributes={"ingress": ingress, "egress": []},
    )


# ---- security group rules --------------------------------------------------


def test_ssh_open_to_world_flagged_high() -> None:
    findings = _run(_sg([{"protocol": "tcp", "from_port": 22, "to_port": 22,
                          "cidrs": ["0.0.0.0/0"]}]))
    ids = {f.rule_id for f in findings}
    assert "AWS-SG-001" in ids
    assert any(f.severity == Severity.HIGH for f in findings if f.rule_id == "AWS-SG-001")


def test_db_port_open_to_world_flagged_critical() -> None:
    findings = _run(_sg([{"protocol": "tcp", "from_port": 5432, "to_port": 5432,
                          "cidrs": ["0.0.0.0/0"]}]))
    db = [f for f in findings if f.rule_id == "AWS-SG-002"]
    assert db and db[0].severity == Severity.CRITICAL


def test_ssh_open_to_specific_cidr_not_flagged() -> None:
    # Context: restricted to a corporate CIDR -> not a finding.
    findings = _run(_sg([{"protocol": "tcp", "from_port": 22, "to_port": 22,
                          "cidrs": ["10.0.0.0/8"]}]))
    assert not findings


def test_all_ports_open_critical() -> None:
    findings = _run(_sg([{"protocol": "-1", "from_port": None, "to_port": None,
                          "cidrs": ["0.0.0.0/0"]}]))
    assert any(f.rule_id == "AWS-SG-003" and f.severity == Severity.CRITICAL for f in findings)


# ---- context: public ALB expected, public RDS critical --------------------


def test_public_load_balancer_is_not_a_finding() -> None:
    alb = DiscoveredResource(
        service="elb", resource_type="load-balancer", resource_id="app-alb",
        region="us-east-1", exposure="public", attributes={"scheme": "internet-facing"},
    )
    assert _run(alb) == []  # internet-facing ALB is expected, not a vulnerability


def test_public_rds_is_critical() -> None:
    rds = DiscoveredResource(
        service="rds", resource_type="db-instance", resource_id="prod-db",
        region="us-east-1", exposure="public",
        attributes={"publicly_accessible": True, "storage_encrypted": True,
                    "backup_retention_days": 7},
    )
    findings = _run(rds)
    pub = [f for f in findings if f.rule_id == "AWS-RDS-001"]
    assert pub and pub[0].severity == Severity.CRITICAL


def test_s3_public_policy_critical() -> None:
    bucket = DiscoveredResource(
        service="s3", resource_type="bucket", resource_id="open",
        region="us-east-1", attributes={"policy_status_public": True, "encryption": True},
    )
    findings = _run(bucket)
    assert any(f.rule_id == "AWS-S3-001" and f.severity == Severity.CRITICAL for f in findings)


def test_iam_user_no_mfa_flagged() -> None:
    user = DiscoveredResource(
        service="iam", resource_type="user", resource_id="alice", region="global",
        attributes={"mfa_devices": 0, "access_keys": []},
    )
    assert any(f.rule_id == "AWS-IAM-001" for f in _run(user))


def test_eks_public_endpoint_open_flagged() -> None:
    eks = DiscoveredResource(
        service="eks", resource_type="cluster", resource_id="prod", region="us-east-1",
        attributes={"endpoint_public_access": True, "public_access_cidrs": ["0.0.0.0/0"]},
    )
    assert any(f.rule_id == "AWS-EKS-001" for f in _run(eks))


def test_findings_carry_compliance_mappings() -> None:
    findings = _run(_sg([{"protocol": "tcp", "from_port": 22, "to_port": 22,
                          "cidrs": ["0.0.0.0/0"]}]))
    assert findings[0].compliance  # non-empty CIS mapping


# ---- posture (reuses Phase 1 scoring) --------------------------------------


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'post.db'}",
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
        # Two cloud findings: a critical SG + an IAM MFA gap.
        session.add(CloudFinding(
            id=uuid.uuid4(), account_id=pk, service="ec2", resource_id="sg-1",
            region="us-east-1", rule_id="AWS-SG-002", scanner="aws-ec2",
            category="security", severity="critical", confidence="high",
            title="db open", fingerprint="AWS-SG-002|sg-1|x", compliance=["CIS-5.2"],
        ))
        session.add(CloudFinding(
            id=uuid.uuid4(), account_id=pk, service="iam", resource_id="alice",
            region="global", rule_id="AWS-IAM-001", scanner="aws-iam",
            category="security", severity="medium", confidence="medium",
            title="no mfa", fingerprint="AWS-IAM-001|alice|y", compliance=["CIS-1.10"],
        ))
        await session.commit()
    yield db, settings, pk
    await db.dispose()


async def test_cloud_posture_scores_domains(account) -> None:
    db, settings, pk = account
    async with db.sessionmaker() as session:
        posture = await CloudPostureService(session, settings).posture(pk)
    assert posture["total_findings"] == 2
    assert posture["overall"] < 100  # findings reduce the score
    keys = {d["key"] for d in posture["domains"]}
    assert {"cloud", "network", "iam"} <= keys
    iam_domain = next(d for d in posture["domains"] if d["key"] == "iam")
    assert iam_domain["applicable"] is True
    assert posture["severity_counts"]["critical"] == 1


async def test_cloud_findings_listed_severity_sorted(account) -> None:
    db, settings, pk = account
    async with db.sessionmaker() as session:
        items, total = await CloudPostureService(session, settings).list_findings(pk)
    assert total == 2
    assert items[0].severity == "critical"  # highest severity first
