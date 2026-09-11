"""End-to-end tests for the reasoning LangGraph workflow."""

from __future__ import annotations

from agents.reasoning.graph import build_reasoning_graph
from agents.reasoning.llm import NullLLMProvider


def _state():
    findings = [
        {"id": "1", "scanner": "docker-rules", "rule_id": "DCK003", "category": "security",
         "severity": "high", "confidence": "high", "title": "runs as root", "description": "d",
         "evidence": "USER root", "file": "Dockerfile", "line": 5, "recommendation": "non-root"},
        {"id": "2", "scanner": "kubernetes-rules", "rule_id": "K8S020", "category": "reliability",
         "severity": "low", "confidence": "high", "title": "no readinessProbe", "description": "d",
         "evidence": "container web", "file": "k8s/deploy.yaml", "line": 10,
         "recommendation": "add probe"},
        {"id": "3", "scanner": "secret-scanner", "rule_id": "SEC001", "category": "secrets",
         "severity": "critical", "confidence": "high", "title": "AWS key", "description": "d",
         "evidence": "AKIA****1234", "file": "config/prod.env", "line": 2,
         "recommendation": "rotate"},
    ]
    return {
        "scan_id": "scan-1",
        "files": [
            {"path": "Dockerfile", "file_type": "dockerfile", "size": 10},
            {"path": "k8s/deploy.yaml", "file_type": "kubernetes", "size": 10},
            {"path": "config/prod.env", "file_type": "env", "size": 10},
        ],
        "findings": findings,
        "relationships": [],
        "domain_findings": [],
        "llm_used": False,
    }


def test_graph_produces_grounded_report() -> None:
    graph = build_reasoning_graph(NullLLMProvider())
    report = graph.invoke(_state())["report"]

    assert report["scan_id"] == "scan-1"
    assert report["llm_used"] is False
    assert report["total_findings"] == 3
    assert report["severity_counts"]["critical"] == 1
    assert report["production_readiness"]["ready"] is False

    valid_ids = {"1", "2", "3"}
    assert report["key_findings"], "expected reasoned findings"
    for kf in report["key_findings"]:
        # Anti-hallucination: every reasoned finding references real evidence.
        assert kf["evidence"]
        assert kf["file"]
        assert kf["source"]
        assert set(kf["source_finding_ids"]).issubset(valid_ids)


def test_graph_key_findings_sorted_by_severity() -> None:
    report = build_reasoning_graph(NullLLMProvider()).invoke(_state())["report"]
    severities = [kf["severity"] for kf in report["key_findings"]]
    assert severities[0] == "critical"  # most severe first


def test_understanding_lists_only_evidenced_technologies() -> None:
    report = build_reasoning_graph(NullLLMProvider()).invoke(_state())["report"]
    techs = set(report["understanding"]["technologies"])
    assert "Docker" in techs
    assert "Kubernetes" in techs
    assert "Terraform" not in techs  # no terraform files -> not claimed
