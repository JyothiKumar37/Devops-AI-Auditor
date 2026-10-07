"""Tests for the Phase 3 controlled AI tool framework.

Covers the safety-critical guarantees: authorization (permission class + scan
scope), argument validation, pagination/result-bounding, and secret redaction at
the tool boundary.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from agents.investigation.redaction import contains_secret, redact_secrets
from agents.investigation.tools import ToolContext, ToolError, ToolPermission
from agents.investigation.tools.analysis_tools import GetFileTool, SearchRepositoryTool
from agents.investigation.tools.base import clamp_limit
from agents.investigation.tools.finding_tools import (
    GetFindingsTool,
    GetFindingTool,
    GetRelatedFindingsTool,
)
from agents.investigation.tools.registry import default_registry
from agents.investigation.tools.scan_tools import GetScanSummaryTool
from core.config import Settings
from core.database import Database
from models.enums import Confidence, FindingCategory, Severity
from models.finding import Finding
from models.scan import RepositoryFile, Scan

SECRET_FILE = (
    "import os\n"
    "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n"
    "password = 'hunter2-super-secret'\n"
    "DB = postgres://admin:topsecretpw@db:5432/app\n"
    "print('ok')\n"
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'inv.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )


@pytest.fixture
async def seeded(tmp_path: Path):
    settings = _settings(tmp_path)
    db = Database(settings)
    await db.create_all()
    scan_id = uuid.uuid4()
    file_id = uuid.uuid4()
    async with db.sessionmaker() as session:
        session.add(
            Scan(
                id=scan_id, repository_name="acme/web", source_type="zip",
                status="completed",
            )
        )
        session.add(
            RepositoryFile(
                id=file_id, scan_id=scan_id, path="app/config.py",
                file_type="other", size=len(SECRET_FILE), checksum="x" * 64,
                content=SECRET_FILE,
            )
        )
        # Five findings of varying severity; one carries a secret in evidence.
        sevs = [Severity.CRITICAL, Severity.HIGH, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for i, sev in enumerate(sevs):
            session.add(
                Finding(
                    id=uuid.uuid4(), scan_id=scan_id, file_id=file_id,
                    category=FindingCategory.SECURITY, severity=sev,
                    confidence=Confidence.HIGH, title=f"Finding {i}",
                    description="desc", evidence="token=AKIAIOSFODNN7EXAMPLE" if i == 0 else "ev",
                    recommendation="fix it", line_number=i + 1,
                    rule_id=f"RULE{i}", scanner="config-rules",
                )
            )
        await session.commit()

    async with db.sessionmaker() as session:
        ctx = ToolContext(
            session=session,
            settings=settings,
            authorized_scan_ids=frozenset({scan_id}),
            granted_permissions=frozenset({ToolPermission.READ}),
        )
        yield ctx, scan_id
    await db.dispose()


# ---- redaction (pure) ------------------------------------------------------


def test_redact_secrets_masks_common_shapes() -> None:
    assert redact_secrets("AKIAIOSFODNN7EXAMPLE") == "[REDACTED]"
    assert "[REDACTED]" in redact_secrets("password = hunter2secret")
    assert "topsecret" not in redact_secrets("postgres://u:topsecretpw@h/db")
    assert redact_secrets("ghp_" + "a" * 36) == "[REDACTED]"
    assert redact_secrets("just normal text") == "just normal text"
    assert contains_secret("AKIAIOSFODNN7EXAMPLE") is True
    assert contains_secret("nothing here") is False


def test_clamp_limit_bounds() -> None:
    assert clamp_limit(1000) == 50
    assert clamp_limit(0) == 20
    assert clamp_limit(5) == 5
    assert clamp_limit(1000, maximum=30) == 30


# ---- authorization ---------------------------------------------------------


async def test_tool_requires_granted_permission(seeded) -> None:
    ctx, scan_id = seeded
    ctx.granted_permissions = frozenset()  # nothing granted
    with pytest.raises(ToolError) as exc:
        await GetScanSummaryTool().invoke(ctx, {"scan_id": str(scan_id)})
    assert exc.value.code == "unauthorized"


async def test_tool_rejects_out_of_scope_scan(seeded) -> None:
    ctx, _ = seeded
    other = uuid.uuid4()
    with pytest.raises(ToolError) as exc:
        await GetFindingsTool().invoke(ctx, {"scan_id": str(other)})
    assert exc.value.code == "unauthorized"


# ---- validation ------------------------------------------------------------


async def test_rejects_unknown_argument(seeded) -> None:
    ctx, scan_id = seeded
    with pytest.raises(ToolError) as exc:
        await GetFindingsTool().invoke(ctx, {"scan_id": str(scan_id), "evil": "x"})
    assert exc.value.code == "invalid_arguments"


async def test_rejects_invalid_severity_filter(seeded) -> None:
    ctx, scan_id = seeded
    with pytest.raises(ToolError) as exc:
        await GetFindingsTool().invoke(ctx, {"scan_id": str(scan_id), "severity": "nope"})
    assert exc.value.code == "invalid_arguments"


async def test_missing_required_argument(seeded) -> None:
    ctx, _ = seeded
    with pytest.raises(ToolError) as exc:
        await GetFindingTool().invoke(ctx, {})
    assert exc.value.code == "invalid_arguments"


# ---- pagination + bounding -------------------------------------------------


async def test_findings_pagination_and_totals(seeded) -> None:
    ctx, scan_id = seeded
    page1 = await GetFindingsTool().invoke(ctx, {"scan_id": str(scan_id), "limit": 2, "offset": 0})
    assert page1.returned == 2
    assert page1.total_available == 5
    assert page1.truncated is True
    # Severity-sorted: critical first.
    assert page1.data[0]["severity"] == "critical"

    last = await GetFindingsTool().invoke(ctx, {"scan_id": str(scan_id), "limit": 2, "offset": 4})
    assert last.returned == 1
    assert last.truncated is False


async def test_severity_filter_applies(seeded) -> None:
    ctx, scan_id = seeded
    res = await GetFindingsTool().invoke(ctx, {"scan_id": str(scan_id), "severity": "high"})
    assert res.returned == 2
    assert all(f["severity"] == "high" for f in res.data)


async def test_related_findings_reasons(seeded) -> None:
    ctx, scan_id = seeded
    listing = await GetFindingsTool().invoke(ctx, {"scan_id": str(scan_id)})
    target = listing.data[0]["finding_id"]
    res = await GetRelatedFindingsTool().invoke(
        ctx, {"scan_id": str(scan_id), "finding_id": target}
    )
    assert res.returned >= 1
    assert all("relation" in r for r in res.data)
    # All share the same file, so same_file should appear.
    assert any("same_file" in r["relation"] for r in res.data)


# ---- secret redaction at the tool boundary --------------------------------


async def test_get_file_redacts_secrets(seeded) -> None:
    ctx, scan_id = seeded
    res = await GetFileTool().invoke(ctx, {"scan_id": str(scan_id), "path": "app/config.py"})
    content = res.data["content"]
    assert "AKIAIOSFODNN7EXAMPLE" not in content
    assert "hunter2-super-secret" not in content
    assert "topsecretpw" not in content
    assert "[REDACTED]" in content


async def test_finding_evidence_redacted(seeded) -> None:
    ctx, scan_id = seeded
    listing = await GetFindingsTool().invoke(ctx, {"scan_id": str(scan_id)})
    crit = listing.data[0]["finding_id"]
    res = await GetFindingTool().invoke(ctx, {"scan_id": str(scan_id), "finding_id": crit})
    assert "AKIAIOSFODNN7EXAMPLE" not in str(res.data)


async def test_search_is_bounded_and_redacted(seeded) -> None:
    ctx, scan_id = seeded
    res = await SearchRepositoryTool().invoke(
        ctx, {"scan_id": str(scan_id), "query": "key", "limit": 3}
    )
    assert res.returned <= 3
    assert "AKIAIOSFODNN7EXAMPLE" not in str(res.data)


# ---- registry --------------------------------------------------------------


async def test_registry_dispatch_and_unknown_tool(seeded) -> None:
    ctx, scan_id = seeded
    registry = default_registry()
    assert "get_findings" in registry.names()
    res = await registry.call("get_findings", ctx, {"scan_id": str(scan_id), "limit": 1})
    assert res.returned == 1
    with pytest.raises(ToolError) as exc:
        await registry.call("execute_sql", ctx, {})
    assert exc.value.code == "not_found"


def test_registry_only_exposes_read_tools() -> None:
    registry = default_registry()
    read = registry.available(frozenset({ToolPermission.READ}))
    assert len(read) == len(registry.names())
    assert all(t.permission == ToolPermission.READ for t in read)
