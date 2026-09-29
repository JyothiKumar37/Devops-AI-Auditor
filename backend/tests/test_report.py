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

from agents.reasoning.llm import LLMMessage, LLMProvider
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
from services.report.sarif_report import render_sarif


class _FakeProvider(LLMProvider):
    name = "fake"

    def __init__(self, payload: str) -> None:
        self._payload = payload

    @property
    def available(self) -> bool:
        return True

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        return self._payload

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
        "executive_summary", "ai_summary", "llm_used", "production_readiness",
        "total_findings", "reviewed_false_positives", "severity_summary",
        "issues_by_severity", "findings_by_domain", "cross_file_risks",
        "remediation_plan", "recommendations", "detailed_findings",
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


def test_sarif_structure_is_valid() -> None:
    doc = json.loads(render_sarif(_build()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "DevOps AI Auditor"

    rules = run["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    # Exactly one rule per distinct rule_id.
    assert len(rule_ids) == len(set(rule_ids))
    assert set(rule_ids) == {"DCK005", "DCK003", "TF004", "K8S001", "SEC010"}

    results = run["results"]
    assert len(results) == 5
    # Every result's ruleIndex resolves to its rule.
    for res in results:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]

    by_rule = {res["ruleId"]: res for res in results}
    # Severity -> SARIF level mapping.
    assert by_rule["DCK005"]["level"] == "error"  # critical
    assert by_rule["DCK003"]["level"] == "error"  # high
    assert by_rule["K8S001"]["level"] == "warning"  # medium
    assert by_rule["SEC010"]["level"] == "note"  # low

    # A finding with a file+line carries a physical location.
    tf = by_rule["TF004"]
    physical = tf["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "main.tf"
    assert physical["region"]["startLine"] == 3
    assert "partialFingerprints" in tf

    # GitHub code-scanning security-severity is set on rules.
    dck5 = next(r for r in rules if r["id"] == "DCK005")
    assert dck5["properties"]["security-severity"] == "9.5"


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


def test_export_sarif(client: TestClient) -> None:
    scan_id = _upload(client)
    response = client.get(f"/api/v1/scans/{scan_id}/report/export?format=sarif")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/sarif+json")
    assert response.headers["content-disposition"].endswith('.sarif"')
    doc = response.json()
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "DevOps AI Auditor"
    assert len(doc["runs"][0]["results"]) > 0
    # Masked evidence: the raw AWS key must never leak into the SARIF either.
    assert "AKIAIOSFODNN7EXAMPLE" not in response.text


def test_export_includes_ai_summary_when_requested(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "agents.ai_assist.service.get_provider",
        lambda _s: _FakeProvider(json.dumps({"summary": "The image runs as root; fix first."})),
    )
    scan_id = _upload(client)
    body = client.get(f"/api/v1/scans/{scan_id}/report/export?format=json&ai=true").json()
    assert body["ai_summary"] and "root" in body["ai_summary"].lower()


def test_export_ai_summary_best_effort_without_provider(client: TestClient) -> None:
    # No LLM configured: ai=true must not break the export; summary is just omitted.
    scan_id = _upload(client)
    with_ai = client.get(f"/api/v1/scans/{scan_id}/report/export?format=json&ai=true").json()
    assert with_ai["ai_summary"] is None
    without = client.get(f"/api/v1/scans/{scan_id}/report/export?format=json").json()
    assert without["ai_summary"] is None


def test_export_excludes_suppressed_findings(client: TestClient) -> None:
    scan_id = _upload(client)
    before = client.get(f"/api/v1/scans/{scan_id}/report/export?format=json").json()

    finding = client.get(f"/api/v1/scans/{scan_id}/findings").json()["items"][0]
    resp = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding['id']}/suppress",
        json={"reason": "false_positive"},
    )
    assert resp.status_code == 201

    after = client.get(f"/api/v1/scans/{scan_id}/report/export?format=json").json()
    assert after["total_findings"] < before["total_findings"]
    assert finding["id"] not in {f["id"] for f in after["detailed_findings"]}


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
