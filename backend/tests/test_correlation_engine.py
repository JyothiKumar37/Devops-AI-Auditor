"""Tests for the cross-file correlation engine (multi-file scenarios)."""

from __future__ import annotations

from typing import Any

from agents.reasoning.correlation import correlate
from models.enums import Confidence, Severity


def _f(fid: str, rule: str, **kw: Any) -> dict[str, Any]:
    base = {
        "id": fid, "scanner": "terraform-rules", "rule_id": rule, "category": "security",
        "severity": "high", "evidence": f"evidence-{fid}", "file": f"file-{fid}.tf",
        "line": 1, "title": f"title-{fid}",
    }
    base.update(kw)
    return base


def _roots(groups) -> set[str]:
    return {g.root_cause for g in groups}


def test_public_database_exposure_combines_rds_sg_and_consumer() -> None:
    findings = [
        _f("a", "TF004", file="infra/rds.tf", evidence="publicly_accessible = true"),
        _f("b", "TF003", file="infra/sg.tf", evidence="cidr=0.0.0.0/0 ports=5432-5432"),
    ]
    index = {
        "k8s_workloads": [
            {"file": "k8s/app.yaml", "name": "api", "namespace": "prod",
             "db_hosts": ["db.rds.amazonaws.com"], "secret_refs": [], "configmap_refs": []}
        ]
    }
    groups = correlate(findings, index)
    group = next(g for g in groups if "Publicly accessible database" in g.root_cause)
    assert group.severity == Severity.CRITICAL
    assert group.confidence == Confidence.HIGH
    assert set(group.member_finding_ids) == {"a", "b"}
    # All three files (RDS, SG, consumer) are combined into the one root cause.
    assert set(group.affected_files) == {"infra/rds.tf", "infra/sg.tf", "k8s/app.yaml"}
    assert "application's data" in group.impact


def test_public_database_not_emitted_without_both_signals() -> None:
    # Only public RDS, no open security group -> no combined group.
    findings = [_f("a", "TF004", file="infra/rds.tf")]
    assert "Publicly accessible database exposed to the internet" not in _roots(
        correlate(findings, {})
    )


def test_cicd_namespace_inconsistency() -> None:
    index = {
        "k8s_namespaces": ["staging"],
        "k8s_workloads": [{"file": "k8s/app.yaml", "name": "api", "namespace": "staging",
                           "images": [], "db_hosts": [], "secret_refs": [], "configmap_refs": []}],
        "cicd": {"deploy_namespaces": ["production"], "has_kubectl": True,
                 "has_terraform_apply": False, "has_image_build": False,
                 "files": [".github/workflows/deploy.yml"]},
    }
    groups = correlate([], index)
    group = next(g for g in groups if "namespace not defined" in g.root_cause)
    assert group.severity == Severity.MEDIUM
    assert any("production" in e for e in group.evidence)


def test_mutable_image_with_ci_build() -> None:
    findings = [
        {"id": "k1", "scanner": "kubernetes-rules", "rule_id": "K8S030", "category": "supply_chain",
         "severity": "medium", "evidence": "image: app:latest", "file": "k8s/deploy.yaml",
         "line": 12, "title": "latest tag"},
    ]
    index = {"cicd": {"has_image_build": True, "files": [".gitlab-ci.yml"],
                      "deploy_namespaces": [], "has_kubectl": False, "has_terraform_apply": False}}
    group = next(g for g in correlate(findings, index) if "mutable ':latest'" in g.root_cause)
    assert group.member_finding_ids == ["k1"]
    assert ".gitlab-ci.yml" in group.affected_files


def test_database_multi_issue_dedupe() -> None:
    findings = [
        _f("1", "TF006", file="infra/rds.tf", severity="high", evidence="storage_encrypted"),
        _f("2", "TF010", file="infra/rds.tf", severity="medium", evidence="backup_retention=0"),
        _f("3", "TF011", file="infra/rds.tf", severity="medium", evidence="deletion_protection"),
    ]
    group = next(g for g in correlate(findings, {}) if "multiple reliability" in g.root_cause)
    assert set(group.member_finding_ids) == {"1", "2", "3"}
    assert group.severity == Severity.HIGH  # max of members
    assert group.affected_files == ["infra/rds.tf"]


def test_duplicate_secret_across_files() -> None:
    findings = [
        {"id": "s1", "scanner": "secret-scanner", "rule_id": "SEC001", "category": "secrets",
         "severity": "critical", "evidence": "AKIA****1234", "file": "a.env", "line": 1,
         "title": "aws"},
        {"id": "s2", "scanner": "secret-scanner", "rule_id": "SEC001", "category": "secrets",
         "severity": "critical", "evidence": "AKIA****1234", "file": "b.env", "line": 1,
         "title": "aws"},
    ]
    group = next(g for g in correlate(findings, {}) if "multiple files" in g.root_cause)
    assert set(group.affected_files) == {"a.env", "b.env"}
    assert set(group.member_finding_ids) == {"s1", "s2"}
    assert group.severity.value == "critical"  # derived from the member findings


def test_duplicate_secret_severity_follows_members() -> None:
    # The same secret duplicated only across down-ranked (LOW) test files is a
    # LOW cross-file risk, not a hardcoded HIGH one.
    findings = [
        {"id": "t1", "scanner": "secret-scanner", "rule_id": "SEC010", "category": "secrets",
         "severity": "low", "evidence": "Pass****123!", "file": "a.test.js", "line": 1,
         "title": "cred"},
        {"id": "t2", "scanner": "secret-scanner", "rule_id": "SEC010", "category": "secrets",
         "severity": "low", "evidence": "Pass****123!", "file": "b.test.js", "line": 1,
         "title": "cred"},
    ]
    group = next(g for g in correlate(findings, {}) if "multiple files" in g.root_cause)
    assert group.severity.value == "low"


def test_kubernetes_wiring_grouping() -> None:
    findings = [
        {"id": "w1", "scanner": "kubernetes-rules", "rule_id": "K8S071", "category": "reliability",
         "severity": "high", "evidence": "targetPort mismatch", "file": "svc.yaml", "line": 2,
         "title": "targetPort"},
        {"id": "w2", "scanner": "kubernetes-rules", "rule_id": "K8S074",
         "category": "configuration", "severity": "medium", "evidence": "ingress port",
         "file": "ing.yaml", "line": 3, "title": "ingress"},
    ]
    group = next(g for g in correlate(findings, {}) if "wiring is inconsistent" in g.root_cause)
    assert set(group.member_finding_ids) == {"w1", "w2"}


def test_no_groups_without_evidence() -> None:
    assert correlate([], {}) == []
