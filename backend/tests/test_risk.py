"""Tests for the deterministic risk-prioritisation engine and its API surface.

Covers the pure scoring function (severity anchoring, factor bonuses, priority
banding, asset-criticality reduction, monotonicity) and the API endpoints
(``/risk-summary`` and ``findings?sort=risk``) over a real scan on SQLite.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app
from services.risk import (
    PRIORITY_HIGH,
    PRIORITY_IMMEDIATE,
    PRIORITY_LOW,
    RiskInput,
    assess_risk,
    priority_rank,
)

# ---------------------------------------------------------------------------
# Pure engine tests (no DB)
# ---------------------------------------------------------------------------


def _inp(**kw: object) -> RiskInput:
    base = {
        "rule_id": "X001",
        "scanner": "docker-rules",
        "category": "best_practice",
        "severity": "medium",
        "confidence": "high",
    }
    base.update(kw)
    return RiskInput(**base)  # type: ignore[arg-type]


def test_score_is_bounded_0_100() -> None:
    for sev in ("info", "low", "medium", "high", "critical"):
        for cat in ("security", "secrets", "reliability", "best_practice"):
            v = assess_risk(_inp(severity=sev, category=cat))
            assert 0 <= v.score <= 100


def test_risk_is_not_just_severity() -> None:
    # Two medium findings: one an exposed secret, one a plain best-practice note.
    secret = assess_risk(
        _inp(
            severity="medium",
            category="secrets",
            scanner="secret-scanner",
            title="Hardcoded AWS key publicly exposed",
        )
    )
    plain = assess_risk(_inp(severity="medium", category="best_practice"))
    assert secret.score > plain.score
    # The exploitable + exposed one should be escalated above its bare severity.
    assert secret.score > plain.factors.severity_base


def test_severity_monotonicity_at_equal_context() -> None:
    scores = [
        assess_risk(_inp(severity=sev)).score
        for sev in ("info", "low", "medium", "high", "critical")
    ]
    assert scores == sorted(scores)
    assert scores[0] < scores[-1]


def test_secret_is_immediate_or_high() -> None:
    v = assess_risk(
        _inp(
            severity="high",
            category="secrets",
            scanner="secret-scanner",
            title="Hardcoded credential",
        )
    )
    assert v.priority in {PRIORITY_IMMEDIATE, PRIORITY_HIGH}
    assert "exploitability" in v.signals


def test_exposure_signal_detected_from_text() -> None:
    v = assess_risk(
        _inp(
            severity="high",
            category="security",
            title="Service exposed via LoadBalancer to the internet",
        )
    )
    assert v.factors.exposure > 0
    assert "internet-exposure" in v.signals


def test_non_production_path_reduces_score() -> None:
    prod = assess_risk(_inp(severity="high", category="security", file_path="app/main.py"))
    test = assess_risk(
        _inp(severity="high", category="security", file_path="tests/test_main.py")
    )
    assert test.score < prod.score
    assert test.factors.asset_criticality < 1.0


def test_low_confidence_reduces_bonus() -> None:
    hi = assess_risk(_inp(severity="high", category="secrets", scanner="secret-scanner",
                          confidence="high"))
    lo = assess_risk(_inp(severity="high", category="secrets", scanner="secret-scanner",
                          confidence="low"))
    assert lo.score <= hi.score


def test_recurrence_increases_score() -> None:
    once = assess_risk(_inp(severity="medium", category="security", recurrence=1))
    many = assess_risk(_inp(severity="medium", category="security", recurrence=5))
    assert many.score >= once.score
    assert many.factors.recurrence > 0


def test_info_finding_is_low_priority() -> None:
    v = assess_risk(_inp(severity="info", category="best_practice"))
    assert v.priority == PRIORITY_LOW


def test_priority_rank_ordering() -> None:
    assert priority_rank(PRIORITY_IMMEDIATE) > priority_rank(PRIORITY_HIGH)
    assert priority_rank(PRIORITY_HIGH) > priority_rank(PRIORITY_LOW)


def test_explanation_mentions_score_and_priority() -> None:
    v = assess_risk(_inp(severity="critical", category="security"))
    assert str(v.score) in v.explanation
    assert "priority" in v.explanation


# ---------------------------------------------------------------------------
# API tests (SQLite-backed scan)
# ---------------------------------------------------------------------------

VULN_DOCKERFILE = """\
FROM ubuntu:latest
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
USER root
EXPOSE 22
CMD ["bash"]
"""

VULN_K8S = """\
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: LoadBalancer
  selector:
    app: api
  ports:
    - port: 80
      targetPort: 8080
"""

FILES = {
    "Dockerfile": VULN_DOCKERFILE,
    "k8s/service.yaml": VULN_K8S,
    "README.md": "# demo\n",
}


def _zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buffer.getvalue()


@pytest.fixture(scope="module")
def client(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    root = tmp_path_factory.mktemp("risk")
    settings = Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{root / 'risk.db'}",
        workspace_root=str(root / "ws"),
        llm_provider="none",
    )
    with TestClient(create_app(settings=settings)) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def scan_id(client: TestClient) -> str:
    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("repo.zip", _zip(FILES), "application/zip")},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_findings_carry_risk_fields(client: TestClient, scan_id: str) -> None:
    items = client.get(f"/api/v1/scans/{scan_id}/findings").json()["items"]
    assert items
    for f in items:
        assert 0 <= f["risk_score"] <= 100
        assert f["risk_priority"] in {"immediate", "high", "normal", "low"}
        assert f["risk_explanation"]
        assert f["risk_factors"] is not None
        assert "exploitability" in f["risk_factors"]


def test_findings_sort_by_risk(client: TestClient, scan_id: str) -> None:
    items = client.get(f"/api/v1/scans/{scan_id}/findings?sort=risk").json()["items"]
    scores = [f["risk_score"] for f in items]
    assert scores == sorted(scores, reverse=True)


def test_risk_summary_endpoint(client: TestClient, scan_id: str) -> None:
    body = client.get(f"/api/v1/scans/{scan_id}/risk-summary").json()
    assert body["total"] >= 1
    assert set(body["counts"]) == {"immediate", "high", "normal", "low"}
    assert sum(body["counts"].values()) == body["total"]
    assert body["max_score"] >= 1
    assert body["top"]
    # Top list is ordered by descending risk score.
    top_scores = [item["risk_score"] for item in body["top"]]
    assert top_scores == sorted(top_scores, reverse=True)
    # The hardcoded secret should be the (or a) top risk.
    assert body["top"][0]["risk_score"] >= 50


def test_priority_filter(client: TestClient, scan_id: str) -> None:
    body = client.get(f"/api/v1/scans/{scan_id}/findings?priority=low").json()
    for f in body["items"]:
        assert f["risk_priority"] == "low"
