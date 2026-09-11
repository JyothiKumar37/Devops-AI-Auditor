"""Tests for the actionlint adapter and CICDScanner dispatch."""

from __future__ import annotations

import json

from scanners.cicd import CICDScanner, actionlint


def test_actionlint_parsing() -> None:
    output = json.dumps(
        [
            {"message": "property 'foo' is not defined", "line": 3, "kind": "syntax-check"},
            {"message": "unexpected key", "line": 8, "kind": "workflow"},
        ]
    )
    findings = actionlint.parse_actionlint_json(output, ".github/workflows/ci.yml")
    assert len(findings) == 2
    assert findings[0].scanner == "actionlint"
    assert findings[0].line_number == 3


def test_actionlint_empty_and_invalid() -> None:
    assert actionlint.parse_actionlint_json("", "x.yml") == []
    assert actionlint.parse_actionlint_json("not json", "x.yml") == []


def test_actionlint_availability_is_bool() -> None:
    assert isinstance(actionlint.is_available(), bool)


def test_scanner_dispatches_by_detected_type() -> None:
    gha = "on: pull_request_target\njobs: {}\n"
    gitlab = 'variables:\n  TOKEN: "literalsecretvalue"\nbuild:\n  script: [make]\n'
    jenkins = 'def password = "hunter2literalvalue"'
    entries = [
        (".github/workflows/ci.yml", "github_actions", gha),
        (".gitlab-ci.yml", "gitlab_ci", gitlab),
        ("Jenkinsfile", "jenkins", jenkins),
    ]
    findings = CICDScanner().analyze_texts(entries)
    scanners = {f.scanner for f in findings}
    assert "github-actions-rules" in scanners
    assert "gitlab-ci-rules" in scanners
    assert "jenkins-rules" in scanners
