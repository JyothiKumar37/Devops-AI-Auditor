"""Tests for the deterministic production-readiness engine."""

from __future__ import annotations

from typing import Any

from agents.reasoning.readiness import _readiness_category, assess


def _f(fid: str, **kw: Any) -> dict[str, Any]:
    base = {
        "id": fid, "scanner": "docker-rules", "rule_id": "DCK001", "category": "supply_chain",
        "severity": "medium", "confidence": "high", "file": "Dockerfile", "title": f"t{fid}",
        "recommendation": "fix it",
    }
    base.update(kw)
    return base


def _cat(**kw: Any) -> str:
    return _readiness_category(_f("x", **kw))


def test_category_mapping() -> None:
    assert _cat(scanner="secret-scanner", category="secrets") == "security"
    assert _cat(category="security", scanner="kubernetes-rules") == "security"
    assert _cat(category="reliability", scanner="kubernetes-rules") == "reliability"
    assert _cat(rule_id="K8S020", category="reliability") == "observability"
    assert _cat(scanner="kubernetes-rules", category="configuration") == "kubernetes"
    assert _cat(scanner="terraform-rules", category="configuration") == "infrastructure"
    assert _cat(scanner="github-actions-rules", category="best_practice") == "cicd"
    assert _cat(scanner="docker-rules", category="efficiency") == "containers"


def test_critical_penalises_far_more_than_info() -> None:
    files = [{"file_type": "dockerfile"}]
    one_critical = assess([_f("1", severity="critical", category="security")], files)
    many_info = assess(
        [_f(str(i), severity="info", category="security") for i in range(10)], files
    )
    # Ten info findings should still score higher than a single critical.
    assert one_critical.score < many_info.score


def test_clean_repo_scores_100() -> None:
    result = assess([], [{"file_type": "dockerfile"}])
    assert result.score == 100
    assert result.ready is True
    assert result.blockers == []


def test_blockers_are_critical_and_top_risks_are_high() -> None:
    findings = [
        _f("c", severity="critical", category="secrets", scanner="secret-scanner",
           title="Public database access"),
        _f("h", severity="high", category="security", scanner="kubernetes-rules",
           title="Privileged Kubernetes container"),
        _f("m", severity="medium", category="reliability", scanner="kubernetes-rules",
           title="Missing resource limits"),
    ]
    result = assess(findings, [{"file_type": "kubernetes"}])
    assert any("Public database access" in b for b in result.blockers)
    assert any("Privileged Kubernetes container" in r for r in result.top_risks)
    assert result.ready is False


def test_non_applicable_categories_excluded_from_overall() -> None:
    # Only container files present: infra/cicd/kubernetes must be non-applicable.
    result = assess([_f("1", severity="high", category="security")], [{"file_type": "dockerfile"}])
    applicable = {c.category for c in result.category_scores if c.applicable}
    assert "containers" in applicable
    assert "infrastructure" not in applicable
    assert "cicd" not in applicable
    assert "kubernetes" not in applicable


def test_every_category_has_an_explanation() -> None:
    result = assess([_f("1", severity="high", category="security")], [{"file_type": "dockerfile"}])
    assert len(result.category_scores) == 8
    assert all(c.explanation for c in result.category_scores)
    assert result.explanation  # overall explanation present


def test_confidence_reduces_penalty() -> None:
    files = [{"file_type": "dockerfile"}]
    high_conf = assess([_f("1", severity="high", category="security", confidence="high")], files)
    low_conf = assess([_f("1", severity="high", category="security", confidence="low")], files)
    assert low_conf.score > high_conf.score  # low confidence penalises less
