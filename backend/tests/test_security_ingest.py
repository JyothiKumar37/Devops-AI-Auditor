"""M2 tests: security event ingestion, normalization, dedup, webhook auth.

No live AWS: AWS-native sources are exercised with recorded fixture dicts through
the normalizers. Internal (verified) sources use a real sqlite DB with real
findings. Webhook auth is tested for valid signature, bad signature, replay and
missing-secret.
"""

from __future__ import annotations

import json
import time
import uuid

import pytest

from models.cloud import CloudAccount, CloudChange, CloudFinding
from models.enums import SecurityEventSourceType
from models.finding import Finding
from models.scan import Scan
from services.security.adapters import aws as aws_adapter
from services.security.webhook_auth import WebhookAuthError, compute_signature
from services.security_service import SecurityService


async def _make_scan_with_finding(sm, repo="acme/app", secret_evidence=False) -> uuid.UUID:
    scan_id = uuid.uuid4()
    async with sm() as session:
        session.add(Scan(id=scan_id, repository_name=repo, source_type="zip", status="completed"))
        evidence = "AKIAIOSFODNN7EXAMPLE leaked" if secret_evidence else "world-open ingress"
        session.add(
            Finding(
                id=uuid.uuid4(), scan_id=scan_id, file_id=None,
                category="security", severity="high", confidence="high",
                title="Security group open to the world", description="0.0.0.0/0 on 22",
                evidence=evidence, recommendation="Restrict the CIDR", rule_id="TF-SG-001",
                scanner="terraform-rules",
            )
        )
        await session.commit()
    return scan_id


async def _make_cloud_account(sm) -> uuid.UUID:
    pk = uuid.uuid4()
    async with sm() as session:
        session.add(CloudAccount(
            id=pk, provider="aws", name="prod", account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/RO", regions=["us-east-1"],
            status="connected",
        ))
        await session.commit()
    return pk


# ---- internal (verified) ingestion ----------------------------------------


async def test_ingest_repo_scan_creates_verified_events(mem_db) -> None:
    sm, settings = mem_db
    scan_id = await _make_scan_with_finding(sm)
    async with sm() as session:
        result = await SecurityService(session, settings).ingest_repo_scan(scan_id)
        await session.commit()
        assert result.created_count == 1
        event = result.created[0]
        assert event.verified is True
        assert event.source_type == SecurityEventSourceType.REPO_SCAN.value
        assert event.severity == "high"
        assert str(scan_id) in event.provenance["scan_id"]


async def test_ingest_dedup_bumps_occurrences(mem_db) -> None:
    sm, settings = mem_db
    scan_id = await _make_scan_with_finding(sm)
    async with sm() as session:
        svc = SecurityService(session, settings)
        first = await svc.ingest_repo_scan(scan_id)
        second = await svc.ingest_repo_scan(scan_id)  # same finding again
        await session.commit()
        assert first.created_count == 1
        assert second.created_count == 0
        assert second.deduplicated_count == 1
        rows, total = await svc.list_events()
        assert total == 1
        assert rows[0].occurrences == 2


async def test_ingest_redacts_secret_evidence(mem_db) -> None:
    sm, settings = mem_db
    scan_id = await _make_scan_with_finding(sm, secret_evidence=True)
    async with sm() as session:
        result = await SecurityService(session, settings).ingest_repo_scan(scan_id)
        await session.commit()
        blob = json.dumps(result.created[0].evidence) + json.dumps(result.created[0].provenance)
        assert "AKIAIOSFODNN7EXAMPLE" not in blob
        assert "[REDACTED]" in blob


async def test_ingest_cloud_account_findings_and_changes(mem_db) -> None:
    sm, settings = mem_db
    account_id = await _make_cloud_account(sm)
    async with sm() as session:
        session.add(CloudFinding(
            id=uuid.uuid4(), account_id=account_id, service="s3", resource_id="open-bucket",
            region="us-east-1", rule_id="AWS-S3-001", scanner="cloud-rules", category="security",
            severity="critical", confidence="high", title="Public bucket", description="",
            recommendation="Block public access", fingerprint="fp1", compliance=["CIS-1"],
        ))
        session.add(CloudChange(
            id=uuid.uuid4(), account_id=account_id, service="ec2", resource_id="sg-1",
            change_type="modified", detail={"opened": "22"}, risk_significant=True,
        ))
        await session.commit()
        svc = SecurityService(session, settings)
        result = await svc.ingest_cloud_account(account_id)
        await session.commit()
        assert result.created_count == 2
        sources = {e.source_type for e in result.created}
        assert SecurityEventSourceType.CLOUD_SCAN.value in sources
        assert SecurityEventSourceType.CLOUD_CHANGE.value in sources
        assert all(e.verified for e in result.created)


# ---- AWS native normalization (fixtures) -----------------------------------


def test_guardduty_normalization() -> None:
    finding = {
        "Id": "gd-1", "Type": "UnauthorizedAccess:EC2/SSHBruteForce", "Severity": 8.0,
        "Title": "SSH brute force", "Description": "many attempts", "Region": "us-east-1",
        "AccountId": "123456789012",
        "Resource": {"InstanceDetails": {"InstanceId": "i-abc"}},
        "Service": {"Action": {"NetworkConnectionAction": {
            "RemoteIpDetails": {"IpAddressV4": "9.9.9.9"}}}},
    }
    ev = aws_adapter.event_from_guardduty(
        finding, account_ref="123456789012", cloud_account_id=None
    )
    assert ev.severity == "critical"
    assert ev.resource_id == "i-abc"
    assert ev.source_ip == "9.9.9.9"
    assert ev.verified is False


async def test_ingest_aws_guardduty_through_service(mem_db) -> None:
    sm, settings = mem_db
    account_id = await _make_cloud_account(sm)
    finding = {
        "Id": "gd-xyz", "Type": "Recon:EC2/PortProbeUnprotectedPort", "Severity": 5.0,
        "Title": "Port probe", "Region": "us-east-1",
        "Resource": {"InstanceDetails": {"InstanceId": "i-xyz"}},
        "Service": {"Action": {}},
    }
    async with sm() as session:
        account = await session.get(CloudAccount, account_id)
        svc = SecurityService(session, settings)
        result = await svc.ingest_aws_findings(
            SecurityEventSourceType.GUARDDUTY.value, [finding], account=account
        )
        await session.commit()
        assert result.created_count == 1
        assert result.created[0].severity == "medium"


# ---- webhook authentication ------------------------------------------------


def _signed(secret: str, body: bytes, *, ts: str | None = None) -> dict[str, str]:
    ts = ts or str(int(time.time()))
    return {"x-timestamp": ts, "x-signature": f"sha256={compute_signature(secret, ts, body)}"}


async def test_webhook_cicd_valid_signature(mem_db) -> None:
    sm, settings = mem_db
    async with sm() as session:
        svc = SecurityService(session, settings)
        await svc.register_source(SecurityEventSourceType.CICD.value, secret="shh")
        await session.commit()
    payload = {"pipeline": "build", "repository": "acme/app", "commit": "abc123",
               "failures": [{"id": "f1", "rule": "trivy-crit", "severity": "critical",
                             "title": "Critical CVE", "resource": "image:tag"}]}
    body = json.dumps(payload).encode()
    async with sm() as session:
        svc = SecurityService(session, settings)
        result = await svc.ingest_webhook(
            SecurityEventSourceType.CICD.value, _signed("shh", body), body
        )
        await session.commit()
        assert result.created_count == 1
        assert result.created[0].severity == "critical"


async def test_webhook_bad_signature_rejected(mem_db) -> None:
    sm, settings = mem_db
    async with sm() as session:
        svc = SecurityService(session, settings)
        await svc.register_source(SecurityEventSourceType.FALCO.value, secret="shh")
        await session.commit()
    body = json.dumps({"rule": "Terminal shell in container", "priority": "Critical"}).encode()
    headers = _signed("WRONG-SECRET", body)
    async with sm() as session:
        svc = SecurityService(session, settings)
        with pytest.raises(WebhookAuthError):
            await svc.ingest_webhook(SecurityEventSourceType.FALCO.value, headers, body)


async def test_webhook_replay_rejected(mem_db) -> None:
    sm, settings = mem_db
    async with sm() as session:
        svc = SecurityService(session, settings)
        await svc.register_source(SecurityEventSourceType.FALCO.value, secret="shh")
        await session.commit()
    body = json.dumps({"rule": "x", "priority": "Warning"}).encode()
    stale = str(int(time.time()) - 10_000)
    headers = _signed("shh", body, ts=stale)
    async with sm() as session:
        svc = SecurityService(session, settings)
        with pytest.raises(WebhookAuthError):
            await svc.ingest_webhook(SecurityEventSourceType.FALCO.value, headers, body)


async def test_webhook_missing_secret_rejected(mem_db) -> None:
    sm, settings = mem_db
    body = json.dumps({"alerts": []}).encode()
    headers = _signed("shh", body)
    async with sm() as session:
        svc = SecurityService(session, settings)
        # No source registered -> no secret configured -> rejected.
        with pytest.raises(WebhookAuthError):
            await svc.ingest_webhook(SecurityEventSourceType.ALERTMANAGER.value, headers, body)
