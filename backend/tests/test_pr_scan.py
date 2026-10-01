"""Tests for incremental PR scanning (new-vs-existing finding separation)."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from core.config import Settings
from core.database import Database
from models.enums import Confidence, FindingCategory, ScanStatus, Severity, SourceType
from models.finding import Finding
from models.scan import RepositoryFile, Scan
from services.pr_scan_service import PRScanService
from services.scm.base import ChangeStatus, SCMChangedFile
from services.scm.fake import FakeSCMProvider, make_pr, make_repo

VULN_K8S = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 1
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
        - name: api
          image: myrepo/api:latest
          securityContext:
            privileged: true
"""


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'pr.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )


def _clone_writes(files: dict[str, str]):
    def _clone(url: str, ref: str | None, dest: Path) -> None:
        for rel, content in files.items():
            p = dest / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
    return _clone


async def _seed_base_scan(db: Database) -> None:
    """A completed base scan for acme/web with one pre-existing Docker finding."""
    async with db.sessionmaker() as session:
        scan = Scan(
            id=uuid.uuid4(),
            repository_name="acme/web",
            source_type=SourceType.GIT,
            status=ScanStatus.COMPLETED,
        )
        session.add(scan)
        await session.flush()
        rf = RepositoryFile(
            id=uuid.uuid4(), scan_id=scan.id, path="Dockerfile",
            file_type="dockerfile", size=10, checksum="x", content="FROM ubuntu:latest\n",
        )
        session.add(rf)
        await session.flush()
        session.add(
            Finding(
                id=uuid.uuid4(), scan_id=scan.id, file_id=rf.id,
                category=FindingCategory.BEST_PRACTICE, severity=Severity.MEDIUM,
                confidence=Confidence.HIGH, title="Base finding", description="",
                recommendation="", rule_id="DCK001", scanner="docker-rules",
                evidence="FROM ubuntu:latest",
            )
        )
        await session.commit()


@pytest.fixture
async def db(tmp_path: Path) -> Database:
    database = Database(_settings(tmp_path))
    await database.create_all()
    await _seed_base_scan(database)
    return database


async def test_incremental_scan_separates_new_findings(tmp_path: Path, db: Database) -> None:
    provider = FakeSCMProvider()
    repo = make_repo("acme", "web")
    provider.add_repo(repo)
    provider.add_pr(
        repo, make_pr(1, head_sha="head1"),
        [SCMChangedFile(path="k8s/app.yaml", status=ChangeStatus.ADDED)],
    )

    async with db.sessionmaker() as session:
        service = PRScanService(
            session=session,
            settings=_settings(tmp_path),
            clone_fn=_clone_writes({"k8s/app.yaml": VULN_K8S}),
        )
        result = await service.scan(provider, repo, 1)
        await session.commit()

    # The PR introduces NEW Kubernetes findings; the pre-existing Docker finding
    # is NOT reported as new (it is on an unchanged file and in the base scan).
    assert result.new_findings >= 1
    assert result.changed_files == 1
    rule_ids = {f["rule_id"] for f in (result.findings_detail or [])}
    assert any(r.startswith("K8S") for r in rule_ids)
    assert "DCK001" not in rule_ids
    # A privileged container is high/critical -> gate fails, risk is non-zero.
    assert result.gate_status == "fail"
    assert result.pr_risk_score > 0
    await db.dispose()


async def test_assigned_policy_overrides_gate(tmp_path: Path, db: Database) -> None:
    # A policy that only WARNS on high/critical should turn the default "fail"
    # gate into "warning" for the same privileged-container PR.
    from services.policy_service import PolicyService

    policy_yaml = (
        "version: 1\nname: lenient\nrules:\n  - id: warn-sev\n"
        "    condition:\n      severity: [critical, high]\n    action: warn\n"
    )
    async with db.sessionmaker() as session:
        svc = PolicyService(session)
        policy = await svc.create("lenient", policy_yaml)
        await svc.assign(policy.id, "repo", "acme/web")
        await session.commit()

    provider = FakeSCMProvider()
    repo = make_repo("acme", "web")
    provider.add_repo(repo)
    provider.add_pr(
        repo, make_pr(3, head_sha="head3"),
        [SCMChangedFile(path="k8s/app.yaml", status=ChangeStatus.ADDED)],
    )
    async with db.sessionmaker() as session:
        service = PRScanService(
            session=session,
            settings=_settings(tmp_path),
            clone_fn=_clone_writes({"k8s/app.yaml": VULN_K8S}),
        )
        result = await service.scan(provider, repo, 3)
        await session.commit()

    assert result.gate_status == "warning"  # policy warn, not default fail
    assert result.policy_result is not None
    assert result.policy_result["policy"] == "lenient"
    await db.dispose()


async def test_clean_pr_passes_gate(tmp_path: Path, db: Database) -> None:
    provider = FakeSCMProvider()
    repo = make_repo("acme", "web")
    provider.add_repo(repo)
    provider.add_pr(
        repo, make_pr(2, head_sha="head2"),
        [SCMChangedFile(path="README.md", status=ChangeStatus.MODIFIED)],
    )
    async with db.sessionmaker() as session:
        service = PRScanService(
            session=session,
            settings=_settings(tmp_path),
            clone_fn=_clone_writes({"README.md": "# docs\n"}),
        )
        result = await service.scan(provider, repo, 2)
        await session.commit()
    assert result.new_findings == 0
    assert result.gate_status == "pass"
    await db.dispose()
