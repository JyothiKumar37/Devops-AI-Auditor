"""Tests for multi-format report generation (JSON, HTML, PDF).

Covers the deterministic builder (aggregation, executive summary, remediation
ordering, stable schema), the three renderers, and the export endpoint.
"""

from __future__ import annotations

import io
import json
import uuid
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app
from models.enums import ScanStatus, SourceType
from models.finding import Finding
from models.scan import Scan
from services.report.builder import build_report_model
from services.report.html_report import render_html
from services.report.json_report import render_json
from services.report.model import REPORT_SCHEMA_VERSION
from services.report.pdf_report import render_pdf

# ---------------------------------------------------------------------------
# Builder (in-memory, no DB)
# ---------------------------------------------------------------------------


def _finding(**kw: object) -> Finding:
    defaults = dict(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        file_id=None,
        category="security",
        severity="high",
        confidence="high",
        title="A finding",
        description="desc",
        evidence="ev",
        recommendation="fix it",
        line_number=1,
        rule_id="DCK003",
        scanner="docker-rules",
    )
    defaults.update(kw)
    return Finding(**defaults)


def _audit_report() -> dict:
    return {
        "llm_used": False,
        "reviewed_false_positives": 1,
        "understanding": {"technologies": ["Docker", "Terraform"], "components": ["api"]},
        "recommendations": ["Adopt least privilege", "Pin images"],
        "production_readiness": {
            "ready": False,
            "score": 62,
            "summary": "Not ready.",
            "confidence": "high",
            "category_scores": [
                {
                    "category": "security",
                    "score": 40,
                    "weight": 0.3,
                    "applicable": True,
                    "findings": 2,
                    "explanation": "sec",
                },
                {
                    "category": "observability",
                    "score": 100,
                    "weight": 0.1,
                    "applicable": False,
                    "findings": 0,
                    "explanation": "n/a",
                },
            ],
            "blockers": ["Container runs as root"],
            "top_risks": ["Hardcoded secret"],
            "next_actions": ["Remove secret"],
            "explanation": "weighted",
        },
        "finding_groups": [
            {
                "root_cause": "Publicly reachable database",
                "category": "security",
                "severity": "critical",
                "confidence": "high",
                "affected_files": ["main.tf", "deploy.yaml"],
                "evidence": ["RDS public", "SG open"],
                "impact": "Data exposure",
                "recommendation": "Make private",
            }
        ],
    }


def _scan() -> Scan:
    return Scan(
        id=uuid.uuid4(),
        repository_name="demo-repo",
        source_type=SourceType.ZIP,
        status=ScanStatus.COMPLETED,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        completed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _build():
    scan = _scan()
    tf_id = uuid.uuid4()
    findings = [
        _finding(rule_id="DCK005", severity="critical", category="secrets",
                 scanner="docker-rules", title="Secret in Dockerfile", line_number=2),
        _finding(rule_id="DCK003", severity="high", category="security",
                 scanner="docker-rules", title="Runs as root", line_number=5),
        _finding(rule_id="TF004", severity="high", category="security", file_id=tf_id,
                 scanner="terraform-rules", title="Public RDS", line_number=3),
        _finding(rule_id="K8S001", severity="medium", category="security",
                 scanner="kubernetes-rules", title="Privileged", line_number=8),
        _finding(rule_id="SEC010", severity="low", category="secrets",
                 scanner="secret-scanner", title="Generic credential", line_number=9),
    ]
    path_by_id = {tf_id: "main.tf"}
    files = [
        {"file_type": "dockerfile", "size": 10},
        {"file_type": "terraform", "size": 20},
        {"file_type": "kubernetes", "size": 30},
    ]
    return build_report_model(scan, findings, path_by_id, files, _audit_report())


def test_builder_aggregates_all_sections() -> None:
    model = _build()
    assert model.schema_version == REPORT_SCHEMA_VERSION
    assert model.repository.name == "demo-repo"
    assert model.repository.total_files == 3
    assert model.repository.technologies == ["Docker", "Terraform"]
    assert model.total_findings == 5

    assert model.severity_summary == {
        "critical": 1, "high": 2, "medium": 1, "low": 1, "info": 0
    }
    # Severity buckets in fixed order.
    assert [b.severity for b in model.issues_by_severity] == [
        "critical", "high", "medium", "low", "info"
    ]
    # Domain views present and named as required by the spec.
    domain_keys = [d.key for d in model.findings_by_domain]
    assert domain_keys == ["security", "docker", "kubernetes", "terraform", "cicd", "secrets"]
    docker = next(d for d in model.findings_by_domain if d.key == "docker")
    assert docker.count == 2  # both docker-rules findings

    # Cross-file risk mapped from finding groups.
    assert model.cross_file_risks[0].root_cause == "Publicly reachable database"

    # Readiness section carried the score and blockers.
    assert model.production_readiness.score == 62
    assert model.production_readiness.rating == "Fair"
    assert model.production_readiness.blockers == ["Container runs as root"]


def test_remediation_plan_ordered_by_severity() -> None:
    model = _build()
    severities = [step.severity for step in model.remediation_plan]
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    assert severities == sorted(severities, key=lambda s: -ranks[s])
    assert model.remediation_plan[0].priority == 1
    assert model.remediation_plan[0].severity == "critical"


def test_remediation_plan_splits_same_rule_by_severity() -> None:
    # A rule that fires at HIGH in prod and LOW in a template/test file must not
    # roll the low-signal file up into the HIGH row.
    scan = _scan()
    findings = [
        _finding(rule_id="SEC009", severity="high", category="secrets",
                 scanner="secret-scanner", title="DB password", file_id=None),
        _finding(rule_id="SEC009", severity="low", category="secrets",
                 scanner="secret-scanner", title="DB password", file_id=None),
    ]
    model = build_report_model(scan, findings, {}, [{"file_type": "env"}], _audit_report())
    sec_steps = [s for s in model.remediation_plan if s.affected_rule_ids == ["SEC009"]]
    assert {s.severity for s in sec_steps} == {"high", "low"}
    assert all(s.finding_count == 1 for s in sec_steps)


def test_detailed_findings_include_evidence_and_location() -> None:
    model = _build()
    tf = next(f for f in model.detailed_findings if f.rule_id == "TF004")
    assert tf.file == "main.tf"
    assert tf.line == 3
    assert tf.evidence is not None


def test_executive_summary_is_manager_friendly() -> None:
    model = _build()
    summary = model.executive_summary
    assert "demo-repo" in summary
    assert "62/100" in summary
    assert "not yet ready" in summary
    assert "1 critical" in summary


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def test_json_is_stable_and_machine_readable() -> None:
    model = _build()
    payload = json.loads(render_json(model))
    assert payload["schema_version"] == REPORT_SCHEMA_VERSION
    # Stable top-level key order.
    assert list(payload.keys()) == [
        "schema_version", "report_id", "generated_at", "title", "repository",
        "executive_summary", "llm_used", "production_readiness", "total_findings",
        "reviewed_false_positives", "severity_summary", "issues_by_severity",
        "findings_by_domain", "cross_file_risks", "remediation_plan",
        "recommendations", "detailed_findings",
    ]
    assert payload["total_findings"] == 5


def test_html_has_all_sections_and_escapes_content() -> None:
    scan = _scan()
    scan.repository_name = "evil<script>alert(1)</script>"
    model = build_report_model(scan, [_finding()], {}, [{"file_type": "dockerfile", "size": 1}],
                               _audit_report())
    html = render_html(model)
    for section in [
        "Executive Summary", "Repository Information", "Production Readiness Score",
        "Issues by Severity", "Findings by Area", "Cross-file Risks",
        "Recommended Remediation Plan", "Detailed Findings",
    ]:
        assert section in html, section
    # The injected script must be escaped, never rendered raw.
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;" in html


def test_pdf_is_valid() -> None:
    pdf = render_pdf(_build())
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000


# ---------------------------------------------------------------------------
# Export endpoint (integration)
# ---------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )
    with TestClient(create_app(settings=settings)) as test_client:
        yield test_client


def _vulnerable_zip() -> bytes:
    dockerfile = (
        b"FROM ubuntu:latest\n"
        b"ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        b"USER root\n"
        b'CMD ["bash"]\n'
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Dockerfile", dockerfile)
    return buffer.getvalue()


def _upload(client: TestClient) -> str:
    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("repo.zip", _vulnerable_zip(), "application/zip")},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_export_json(client: TestClient) -> None:
    scan_id = _upload(client)
    response = client.get(f"/api/v1/scans/{scan_id}/report/export?format=json")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert "attachment" in response.headers["content-disposition"]
    assert response.headers["content-disposition"].endswith('.json"')
    body = response.json()
    assert body["schema_version"] == REPORT_SCHEMA_VERSION
    assert body["total_findings"] > 0
    assert body["detailed_findings"], "expected detailed findings"
    # The raw AWS key must never appear (evidence is masked upstream).
    assert "AKIAIOSFODNN7EXAMPLE" not in response.text


def test_export_html(client: TestClient) -> None:
    scan_id = _upload(client)
    response = client.get(f"/api/v1/scans/{scan_id}/report/export?format=html")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Executive Summary" in response.text
    assert "Detailed Findings" in response.text
    assert "AKIAIOSFODNN7EXAMPLE" not in response.text


def test_export_pdf(client: TestClient) -> None:
    scan_id = _upload(client)
    response = client.get(f"/api/v1/scans/{scan_id}/report/export?format=pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-")


def test_export_inline_disposition(client: TestClient) -> None:
    scan_id = _upload(client)
    response = client.get(
        f"/api/v1/scans/{scan_id}/report/export?format=json&download=false"
    )
    assert response.status_code == 200
    assert response.headers["content-disposition"].startswith("inline")


def test_export_invalid_format_rejected(client: TestClient) -> None:
    scan_id = _upload(client)
    assert client.get(f"/api/v1/scans/{scan_id}/report/export?format=xml").status_code == 422


def test_export_unknown_scan_404(client: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/v1/scans/{missing}/report/export?format=json").status_code == 404
