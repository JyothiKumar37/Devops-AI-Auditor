"""M4 tests: deterministic root-cause clustering, the tool, scan diff, history."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agents.investigation.correlation import group_findings
from agents.investigation.engine import InvestigationEngine
from agents.investigation.tools import ToolContext, ToolPermission
from agents.investigation.tools.analysis_tools import GetScanDiffTool
from agents.investigation.tools.finding_tools import GetRootCauseGroupsTool
from agents.reasoning.llm import LLMMessage, LLMProvider
from core.config import Settings
from core.database import Database
from models.enums import Confidence, FindingCategory, Severity
from models.finding import Finding
from models.scan import RepositoryFile, Scan


def _finding(scanner: str, category: FindingCategory, severity: Severity, path: str) -> Finding:
    return Finding(
        id=uuid.uuid4(), scan_id=uuid.uuid4(), file_id=uuid.uuid4(),
        category=category, severity=severity, confidence=Confidence.HIGH,
        title="t", description="d", evidence="e", recommendation="r",
        line_number=1, rule_id="R", scanner=scanner,
    )


def _item(scanner: str, category: FindingCategory, severity: Severity, path: str):
    return (_finding(scanner, category, severity, path), path)


def test_group_findings_themes_and_order() -> None:
    items = [
        _item("kubernetes-rules", FindingCategory.RELIABILITY, Severity.HIGH, "k8s/d.yaml"),
        _item("kubernetes-rules", FindingCategory.RELIABILITY, Severity.MEDIUM, "k8s/d.yaml"),
        _item("secret-scanner", FindingCategory.SECRETS, Severity.CRITICAL, ".env"),
        _item("docker-rules", FindingCategory.BEST_PRACTICE, Severity.LOW, "Dockerfile"),
    ]
    groups = group_findings(items)
    themes = [g.theme for g in groups]
    assert "Kubernetes resource & reliability management" in themes
    assert "Secret exposure" in themes
    # Severity-weighted: k8s pair (high+medium=5) outranks the single critical (4).
    assert groups[0].theme == "Kubernetes resource & reliability management"
    k8s = next(g for g in groups if g.theme.startswith("Kubernetes"))
    assert k8s.count == 2
    assert k8s.to_dict()["files"] == ["k8s/d.yaml"]


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'corr.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )


async def _seed_scan(session, repo: str, created: datetime, n_findings: int) -> uuid.UUID:
    scan_id = uuid.uuid4()
    file_id = uuid.uuid4()
    session.add(
        Scan(
            id=scan_id, repository_name=repo, source_type="zip", status="completed",
            created_at=created,
        )
    )
    session.add(
        RepositoryFile(
            id=file_id, scan_id=scan_id, path="k8s/deploy.yaml", file_type="other",
            size=10, checksum="x" * 64, content="a\nb\n",
        )
    )
    for i in range(n_findings):
        session.add(
            Finding(
                id=uuid.uuid4(), scan_id=scan_id, file_id=file_id,
                category=FindingCategory.RELIABILITY, severity=Severity.HIGH,
                confidence=Confidence.HIGH, title=f"issue {i}", description="d",
                evidence="e", recommendation="fix", line_number=i + 1,
                rule_id=f"K8S{i}", scanner="kubernetes-rules",
            )
        )
    return scan_id


@pytest.fixture
async def two_scans(tmp_path: Path):
    settings = _settings(tmp_path)
    db = Database(settings)
    await db.create_all()
    now = datetime.now(UTC)
    async with db.sessionmaker() as session:
        base_id = await _seed_scan(session, "acme/web", now - timedelta(hours=2), 1)
        head_id = await _seed_scan(session, "acme/web", now, 3)
        await session.commit()
    yield db, settings, base_id, head_id
    await db.dispose()


async def test_root_cause_tool(two_scans) -> None:
    db, settings, _, head_id = two_scans
    async with db.sessionmaker() as session:
        ctx = ToolContext(
            session=session, settings=settings,
            authorized_scan_ids=frozenset({head_id}),
            granted_permissions=frozenset({ToolPermission.READ}),
        )
        res = await GetRootCauseGroupsTool().invoke(ctx, {"scan_id": str(head_id)})
    assert res.returned >= 1
    assert res.data[0]["theme"].startswith("Kubernetes")
    assert res.data[0]["count"] == 3


async def test_scan_diff_tool_detects_new_findings(two_scans) -> None:
    db, settings, base_id, head_id = two_scans
    async with db.sessionmaker() as session:
        ctx = ToolContext(
            session=session, settings=settings,
            authorized_scan_ids=frozenset({base_id, head_id}),
            granted_permissions=frozenset({ToolPermission.READ}),
        )
        res = await GetScanDiffTool().invoke(ctx, {"scan_id": str(head_id)})
    # Head has more findings than base -> new findings detected.
    assert res.data["summary"]["new"] >= 1
    assert "readiness_delta" in res.data


class _HistProvider(LLMProvider):
    name = "hist"

    def __init__(self, head_id: str) -> None:
        self._head = head_id
        self._decided = False

    @property
    def available(self) -> bool:
        return True

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        system = messages[0].content
        if "investigation planner" in system:
            return json.dumps({"intent": "why did score change", "plan": []})
        if "investigation agent" in system:
            if not self._decided:
                self._decided = True
                return json.dumps(
                    {
                        "action": "call_tool", "tool": "get_scan_diff",
                        "tool_args": {"scan_id": self._head}, "purpose": "compare",
                    }
                )
            return json.dumps({"action": "final"})
        return json.dumps(
            {"answer": "New reliability findings lowered the score.", "cited_files": []}
        )


async def test_historical_investigation_uses_diff(two_scans) -> None:
    db, settings, _, head_id = two_scans
    provider = _HistProvider(str(head_id))
    async with db.sessionmaker() as session:
        engine = await InvestigationEngine.build(
            session, settings, scan_id=head_id, provider=provider
        )
        result = await engine.investigate("Why did our score drop?")
    assert any(e["tool"] == "get_scan_diff" for e in result.evidence)
    assert "score" in result.answer.lower()
