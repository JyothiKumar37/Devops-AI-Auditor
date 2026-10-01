"""Tests for the deterministic policy engine (parse + evaluate)."""

from __future__ import annotations

import pytest

from services.policy_engine import (
    STATUS_FAIL,
    STATUS_PASS,
    STATUS_WARN,
    PolicyError,
    evaluate,
    parse_policy,
)

POLICY = """\
version: 1
name: production-policy
rules:
  - id: no-new-critical
    condition:
      severity: [critical, high]
      is_new: true
    action: fail
  - id: no-root-container
    condition:
      rule_id: DCK003
    action: fail
  - id: warn-medium
    condition:
      severity: medium
    action: warn
  - id: prod-only-secrets
    condition:
      category: secrets
      environment: production
    action: fail
"""


def _finding(**kw: object) -> dict:
    base = {
        "rule_id": "X", "scanner": "s", "category": "security",
        "severity": "low", "confidence": "high", "file": "app/main.py",
        "risk_score": 10, "is_new": True,
    }
    base.update(kw)
    return base


def test_parse_valid_policy() -> None:
    spec = parse_policy(POLICY)
    assert spec["name"] == "production-policy"
    assert len(spec["rules"]) == 4


@pytest.mark.parametrize(
    "bad",
    [
        "name: x",  # no rules
        "rules: []\nname: x",  # empty rules
        "name: x\nrules:\n  - id: a\n    action: nope\n    condition: {severity: high}",
        "name: x\nrules:\n  - id: a\n    action: fail\n    condition: {bogus: 1}",
        "just a string",
    ],
)
def test_parse_rejects_invalid(bad: str) -> None:
    with pytest.raises(PolicyError):
        parse_policy(bad)


def test_evaluate_pass_when_clean() -> None:
    spec = parse_policy(POLICY)
    result = evaluate(spec, [_finding(severity="low")])
    assert result.status == STATUS_PASS
    assert result.violations == []


def test_evaluate_fail_on_new_critical() -> None:
    spec = parse_policy(POLICY)
    result = evaluate(spec, [_finding(severity="critical", is_new=True)])
    assert result.status == STATUS_FAIL
    assert any(v["rule_id"] == "no-new-critical" for v in result.violations)


def test_existing_critical_does_not_fail_is_new_rule() -> None:
    spec = parse_policy(POLICY)
    # Same critical finding but pre-existing (is_new False) -> the is_new rule
    # does not match; nothing else matches a critical -> pass.
    result = evaluate(spec, [_finding(severity="critical", is_new=False)])
    assert result.status == STATUS_PASS


def test_evaluate_warn_on_medium() -> None:
    spec = parse_policy(POLICY)
    result = evaluate(spec, [_finding(severity="medium", is_new=False)])
    assert result.status == STATUS_WARN


def test_rule_id_condition() -> None:
    spec = parse_policy(POLICY)
    result = evaluate(spec, [_finding(rule_id="DCK003", severity="low", is_new=False)])
    assert result.status == STATUS_FAIL
    assert any(v["rule_id"] == "no-root-container" for v in result.violations)


def test_environment_scoping() -> None:
    spec = parse_policy(POLICY)
    secret = _finding(category="secrets", severity="low", is_new=False)
    # Not production -> the prod-only rule is skipped -> pass.
    assert evaluate(spec, [secret], environment="staging").status == STATUS_PASS
    # Production -> the rule applies -> fail.
    assert evaluate(spec, [secret], environment="production").status == STATUS_FAIL


def test_min_risk_score_condition() -> None:
    spec = parse_policy(
        "name: risk\nrules:\n  - id: high-risk\n    condition:\n      min_risk_score: 70\n"
        "    action: fail"
    )
    assert evaluate(spec, [_finding(risk_score=80)]).status == STATUS_FAIL
    assert evaluate(spec, [_finding(risk_score=50)]).status == STATUS_PASS


def test_path_condition_glob() -> None:
    spec = parse_policy(
        "name: p\nrules:\n  - id: infra\n    condition:\n      path: '*.tf'\n    action: fail"
    )
    assert evaluate(spec, [_finding(file="main.tf")]).status == STATUS_FAIL
    assert evaluate(spec, [_finding(file="app/main.py")]).status == STATUS_PASS
