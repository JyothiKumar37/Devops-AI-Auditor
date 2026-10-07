"""M6 tests: AI remediation planner (deterministic estimate, validated, no mutation)."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from core.config import Settings
from core.database import Database
from core.exceptions import ValidationError
from models.enums import Confidence, FindingCategory, Severity
from models.finding import Finding
from models.scan import RepositoryFile, Scan
from services.remediation_plan_service import RemediationPlanService


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'rem.db'}",
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
    fids = [uuid.uuid4(), uuid.uuid4()]
    async with db.sessionmaker() as session:
        session.add(
            Scan(id=scan_id, repository_name="acme/web", source_type="zip", status="completed")
        )
        session.add(
            RepositoryFile(
                id=file_id, scan_id=scan_id, path="k8s/deploy.yaml", file_type="kubernetes",
                size=10, checksum="x" * 64, content="a\nb\n",
            )
        )
        for i, fid in enumerate(fids):
            session.add(
                Finding(
                    id=fid, scan_id=scan_id, file_id=file_id,
                    category=FindingCategory.RELIABILITY,
                    severity=Severity.HIGH if i == 0 else Severity.MEDIUM,
                    confidence=Confidence.HIGH, title=f"Missing limits {i}",
                    description="d", evidence="e",
                    recommendation="Add CPU/memory requests and limits.",
                    line_number=i + 1, rule_id=f"K8S00{i}", scanner="kubernetes-rules",
                )
            )
        await session.commit()
    yield db, settings, scan_id, [str(f) for f in fids]
    await db.dispose()


async def test_auto_plan_targets_by_risk(seeded) -> None:
    db, settings, scan_id, fids = seeded
    async with db.sessionmaker() as session:
        plan = await RemediationPlanService(session, settings).plan(scan_id)
    assert plan.status == "proposed"
    assert plan.requires_approval is True
    assert plan.label == "AI Remediation Plan"
    assert len(plan.steps) >= 1
    # Every step is tied to a real finding and carries its deterministic recommendation.
    assert all(s.finding_id in fids for s in plan.steps)
    assert all("limits" in s.deterministic_recommendation.lower() for s in plan.steps)
    # Resolving reliability findings should not decrease the readiness score.
    assert plan.estimated_score_after >= plan.estimated_score_before
    assert plan.estimated_score_delta == plan.estimated_score_after - plan.estimated_score_before
    assert "ESTIMATE" in plan.estimate_note


async def test_explicit_finding_ids(seeded) -> None:
    db, settings, scan_id, fids = seeded
    async with db.sessionmaker() as session:
        plan = await RemediationPlanService(session, settings).plan(
            scan_id, finding_ids=[uuid.UUID(fids[0])]
        )
    assert len(plan.steps) == 1
    assert plan.steps[0].finding_id == fids[0]
    assert plan.expected_findings_resolved == [fids[0]]


async def test_unknown_finding_ids_rejected(seeded) -> None:
    db, settings, scan_id, _ = seeded
    async with db.sessionmaker() as session:
        with pytest.raises(ValidationError):
            await RemediationPlanService(session, settings).plan(
                scan_id, finding_ids=[uuid.uuid4()]  # not in this scan
            )
