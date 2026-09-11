"""Tests for the reasoning agents (fallbacks, grounding, anti-hallucination)."""

from __future__ import annotations

from agents.reasoning import agents
from agents.reasoning.llm import LLMMessage, LLMProvider, NullLLMProvider


def _finding(**kwargs):
    base = {
        "id": "1", "scanner": "docker-rules", "rule_id": "DCK003", "category": "security",
        "severity": "high", "confidence": "high", "title": "runs as root",
        "description": "desc", "evidence": "USER root", "file": "Dockerfile", "line": 5,
        "recommendation": "use non-root",
    }
    base.update(kwargs)
    return base


NULL = NullLLMProvider()


def test_repository_understanding_derives_tech_from_files_only() -> None:
    state = {
        "files": [
            {"path": "Dockerfile", "file_type": "dockerfile", "size": 10},
            {"path": "k8s/x.yaml", "file_type": "kubernetes", "size": 10},
        ],
        "findings": [_finding()],
    }
    out = agents.repository_understanding(state, NULL)["understanding"]
    assert set(out["technologies"]) == {"Docker", "Kubernetes"}
    # No technology is claimed that is not evidenced by a file type.
    assert "Terraform" not in out["technologies"]


def test_security_agent_grounds_every_finding() -> None:
    findings = [_finding(id="1"), _finding(id="2", category="reliability")]
    out = agents.security_reasoning({"findings": findings, "domain_findings": []}, NULL)
    produced = out["domain_findings"]
    # Only the security finding is reasoned by the security agent.
    assert len(produced) == 1
    assert produced[0]["source_finding_ids"] == ["1"]
    assert produced[0]["evidence"] == "USER root"
    assert produced[0]["file"] == "Dockerfile"


class _HallucinatingProvider(LLMProvider):
    name = "hallucinating"

    @property
    def available(self) -> bool:
        return True

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        # Returns a finding referencing an id that was never provided.
        return (
            '{"findings": [{"title": "Invented", "category": "security", "severity": "high",'
            ' "confidence": "high", "evidence": "made up", "source": "x", "reasoning": "r",'
            ' "recommendation": "rec", "source_finding_ids": ["999"]}]}'
        )


def test_anti_hallucination_drops_ungrounded_llm_findings() -> None:
    findings = [_finding(id="1")]
    out = agents.security_reasoning(
        {"findings": findings, "domain_findings": []}, _HallucinatingProvider()
    )
    produced = out["domain_findings"]
    # The invented finding (id 999) is rejected; the deterministic fallback is used.
    assert all(af["source_finding_ids"] == ["1"] for af in produced)
    assert all(af["title"] != "Invented" for af in produced)


def test_false_positive_review_flags_low_impact_in_test_paths() -> None:
    findings = [
        _finding(id="1", severity="low", category="best_practice", file="tests/fixtures/app.yaml"),
        _finding(id="2", severity="critical", file="Dockerfile"),
    ]
    out = agents.false_positive_review({"findings": findings}, NULL)["false_positives"]
    flagged = {a["finding_id"] for a in out if a["is_false_positive"]}
    assert flagged == {"1"}  # critical in prod path is not a false positive


def test_prioritize_removes_false_positives_and_sorts() -> None:
    domain = [
        agents._dump(agents._to_ai_finding(_finding(id="1", severity="low"), "r")),
        agents._dump(agents._to_ai_finding(_finding(id="2", severity="critical"), "r")),
    ]
    state = {
        "domain_findings": domain,
        "false_positives": [{"finding_id": "1", "is_false_positive": True}],
    }
    prioritized = agents.prioritize(state, NULL)["prioritized"]
    assert [af["source_finding_ids"] for af in prioritized] == [["2"]]


def test_production_readiness_node_scores_findings() -> None:
    state = {
        "findings": [
            _finding(id="1", severity="critical", category="secrets", scanner="secret-scanner"),
            _finding(id="2", severity="low", category="efficiency", scanner="docker-rules"),
        ],
        "files": [{"file_type": "dockerfile"}],
        "false_positives": [],
    }
    readiness = agents.production_readiness(state, NULL)["readiness"]
    assert readiness["ready"] is False  # a critical finding blocks readiness
    assert 0 <= readiness["score"] <= 100
    assert readiness["blockers"]  # critical becomes a blocker
    assert readiness["category_scores"]


def test_production_readiness_excludes_confirmed_false_positives() -> None:
    state = {
        "findings": [_finding(id="1", severity="critical", category="secrets",
                              scanner="secret-scanner")],
        "files": [{"file_type": "dockerfile"}],
        "false_positives": [{"finding_id": "1", "is_false_positive": True}],
    }
    readiness = agents.production_readiness(state, NULL)["readiness"]
    # The only finding is a confirmed FP, so it does not count against readiness.
    assert readiness["ready"] is True
    assert readiness["blockers"] == []


def test_correlation_from_relationships_and_duplicate_secrets() -> None:
    relationships = [
        {"id": "r1", "title": "Service targetPort mismatch", "description": "d",
         "severity": "high", "file": "svc.yaml", "recommendation": "align"},
    ]
    findings = [
        {"id": "s1", "scanner": "secret-scanner", "evidence": "AKIA****1234", "file": "a.env"},
        {"id": "s2", "scanner": "secret-scanner", "evidence": "AKIA****1234", "file": "b.env"},
    ]
    out = agents.cross_file_correlation(
        {"relationships": relationships, "findings": findings}, NULL
    )["correlations"]
    titles = {c["title"] for c in out}
    assert "Service targetPort mismatch" in titles
    assert "Same secret referenced in multiple files" in titles
