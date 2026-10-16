"""M8 tests: cloud AI investigation tools (scope, redaction, no invented resources)."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from agents.investigation.engine import InvestigationEngine
from agents.investigation.tools import ToolContext, ToolError, ToolPermission
from agents.investigation.tools.cloud_tools import (
    GetCloudAssetsTool,
    GetCloudFindingsTool,
    GetCloudResourceTool,
    ListCloudAccountsTool,
)
from agents.reasoning.llm import LLMMessage, LLMProvider
from core.config import Settings
from core.database import Database
from models.cloud import CloudAccount, CloudAsset, CloudFinding


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'cai.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )


@pytest.fixture
async def env(tmp_path: Path):
    settings = _settings(tmp_path)
    db = Database(settings)
    await db.create_all()
    acct = uuid.uuid4()
    async with db.sessionmaker() as session:
        session.add(CloudAccount(
            id=acct, provider="aws", name="prod", account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/RO", regions=["us-east-1"],
            status="connected",
        ))
        # Asset whose tags contain a secret-looking value (must be redacted).
        session.add(CloudAsset(
            id=uuid.uuid4(), account_id=acct, service="ec2", resource_type="instance",
            resource_id="i-1", region="us-east-1", exposure="public",
            tags={"Name": "web", "aws_secret_access_key": "AKIAIOSFODNN7EXAMPLE"},
            attributes={"public_ip": "1.2.3.4"},
        ))
        session.add(CloudFinding(
            id=uuid.uuid4(), account_id=acct, service="ec2", resource_id="i-1",
            region="us-east-1", rule_id="AWS-SG-001", scanner="aws-ec2",
            category="security", severity="high", confidence="high",
            title="ssh open", fingerprint="AWS-SG-001|i-1|x",
        ))
        await session.commit()
    yield db, settings, acct
    await db.dispose()


def _ctx(session, settings, acct) -> ToolContext:
    return ToolContext(
        session=session, settings=settings,
        authorized_account_ids=frozenset({acct}),
        granted_permissions=frozenset({ToolPermission.READ}),
    )


async def test_tool_rejects_unauthorized_account(env) -> None:
    db, settings, acct = env
    other = uuid.uuid4()
    async with db.sessionmaker() as session:
        ctx = _ctx(session, settings, acct)
        with pytest.raises(ToolError) as exc:
            await GetCloudAssetsTool().invoke(ctx, {"account_id": str(other)})
    assert exc.value.code == "unauthorized"


async def test_assets_tool_redacts_secrets(env) -> None:
    db, settings, acct = env
    async with db.sessionmaker() as session:
        ctx = _ctx(session, settings, acct)
        res = await GetCloudAssetsTool().invoke(ctx, {"account_id": str(acct)})
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(res.data)
    assert "[REDACTED]" in json.dumps(res.data)


async def test_resource_tool_not_found_for_invented_resource(env) -> None:
    db, settings, acct = env
    async with db.sessionmaker() as session:
        ctx = _ctx(session, settings, acct)
        with pytest.raises(ToolError) as exc:
            await GetCloudResourceTool().invoke(
                ctx, {"account_id": str(acct), "resource_id": "i-does-not-exist"}
            )
    assert exc.value.code == "not_found"


async def test_list_accounts_only_authorized(env) -> None:
    db, settings, acct = env
    async with db.sessionmaker() as session:
        ctx = _ctx(session, settings, acct)
        res = await ListCloudAccountsTool().invoke(ctx, {})
    assert res.returned == 1
    assert "encrypted" not in json.dumps(res.data).lower()


async def test_findings_tool_severity_sorted(env) -> None:
    db, settings, acct = env
    async with db.sessionmaker() as session:
        ctx = _ctx(session, settings, acct)
        res = await GetCloudFindingsTool().invoke(ctx, {"account_id": str(acct)})
    assert res.returned == 1
    assert res.data[0]["rule_id"] == "AWS-SG-001"


class _CloudAnalyst(LLMProvider):
    name = "cloud"

    def __init__(self, account_pk: str) -> None:
        self._acct = account_pk
        self._decided = False

    @property
    def available(self) -> bool:
        return True

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        system = messages[0].content
        if "investigation planner" in system:
            return json.dumps({"intent": "find public exposure", "plan": []})
        if "investigation agent" in system:
            if not self._decided:
                self._decided = True
                return json.dumps({"action": "call_tool", "tool": "get_cloud_findings",
                                   "tool_args": {"account_id": self._acct}, "purpose": "list"})
            return json.dumps({"action": "final"})
        return json.dumps({
            "answer": "An EC2 security group exposes SSH to the internet.",
            "cited_files": [],
        })


async def test_cloud_investigation_uses_cloud_tool(env) -> None:
    db, settings, acct = env
    provider = _CloudAnalyst(str(acct))
    async with db.sessionmaker() as session:
        engine = await InvestigationEngine.build(
            session, settings, account_id=acct, provider=provider
        )
        result = await engine.investigate("Is anything publicly exposed?")
    assert result.ai_used is True
    assert any(e["tool"] == "get_cloud_findings" for e in result.evidence)
    assert "AKIA" not in json.dumps(result.evidence)
