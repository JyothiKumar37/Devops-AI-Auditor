"""Tests for the Hadolint and Trivy output mapping (no binaries required)."""

from __future__ import annotations

import json

from models.enums import Severity
from scanners.docker import hadolint, trivy


def test_hadolint_mapping() -> None:
    output = json.dumps(
        [
            {"line": 1, "code": "DL3007", "level": "warning", "message": "Using latest tag"},
            {"line": 5, "code": "DL3002", "level": "error", "message": "Last USER is root"},
            {"line": 9, "code": "DL3059", "level": "info", "message": "Consecutive RUN"},
        ]
    )
    findings = hadolint.parse_hadolint_json(output, "Dockerfile")
    assert len(findings) == 3
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["DL3007"].severity == Severity.MEDIUM
    assert by_rule["DL3002"].severity == Severity.HIGH
    assert by_rule["DL3059"].severity == Severity.LOW
    assert all(f.scanner == "hadolint" for f in findings)
    assert by_rule["DL3002"].line_number == 5


def test_hadolint_handles_empty_and_invalid() -> None:
    assert hadolint.parse_hadolint_json("", "Dockerfile") == []
    assert hadolint.parse_hadolint_json("not json", "Dockerfile") == []


def test_trivy_mapping_summarises_by_severity() -> None:
    report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {"Severity": "CRITICAL"},
                    {"Severity": "CRITICAL"},
                    {"Severity": "HIGH"},
                    {"Severity": "LOW"},
                ]
            }
        ]
    }
    findings = trivy.parse_trivy_image_json(json.dumps(report), "Dockerfile", "ubuntu:20.04", 1)
    by_sev = {f.severity: f for f in findings}
    assert by_sev[Severity.CRITICAL].title.startswith("Base image 'ubuntu:20.04' has 2 critical")
    assert by_sev[Severity.HIGH].title.startswith("Base image 'ubuntu:20.04' has 1 high")
    assert all(f.rule_id == "DCK013" and f.scanner == "trivy" for f in findings)


def test_trivy_no_vulnerabilities() -> None:
    assert trivy.parse_trivy_image_json(json.dumps({"Results": []}), "Dockerfile", "x", 1) == []
    assert trivy.parse_trivy_image_json("", "Dockerfile", "x", 1) == []
