"""Deterministic policy-as-code engine.

Policies are small YAML documents describing when a scan should fail or warn.
They are parsed with ``yaml.safe_load`` (no code execution) and evaluated with
plain dict comparisons (no ``eval``), so a malicious policy can at worst be
rejected as invalid - never run code or exhaust resources.

Policy shape::

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

A rule MATCHES a finding when every key in its ``condition`` matches. A ``fail``
rule with any match makes the overall result FAIL; a ``warn`` rule makes it WARN
(unless something already failed). ``ignore`` never fails.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

import yaml

VALID_ACTIONS = {"fail", "warn", "ignore"}
_CONDITION_KEYS = {
    "severity", "min_risk_score", "rule_id", "scanner", "category",
    "confidence", "path", "is_new", "environment",
}

STATUS_PASS = "pass"
STATUS_WARN = "warning"
STATUS_FAIL = "fail"


class PolicyError(ValueError):
    """A policy document is structurally invalid."""


@dataclass(frozen=True, slots=True)
class RuleResult:
    id: str
    action: str
    matched: int
    passed: bool
    sample: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class PolicyResult:
    status: str  # pass | warning | fail
    rules: list[RuleResult]
    violations: list[dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "rules": [
                {"id": r.id, "action": r.action, "matched": r.matched, "passed": r.passed}
                for r in self.rules
            ],
            "violations": self.violations,
        }


def parse_policy(yaml_text: str) -> dict[str, Any]:
    """Parse + validate a policy YAML document, or raise ``PolicyError``."""
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"Policy is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("Policy must be a YAML mapping.")
    if not isinstance(data.get("name"), str) or not data["name"].strip():
        raise PolicyError("Policy must have a non-empty 'name'.")
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        raise PolicyError("Policy must define a non-empty 'rules' list.")
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise PolicyError(f"Rule #{i + 1} must be a mapping.")
        if not isinstance(rule.get("id"), str) or not rule["id"].strip():
            raise PolicyError(f"Rule #{i + 1} must have a string 'id'.")
        action = rule.get("action")
        if action not in VALID_ACTIONS:
            raise PolicyError(
                f"Rule '{rule.get('id')}' has invalid action '{action}' "
                f"(expected one of {sorted(VALID_ACTIONS)})."
            )
        condition = rule.get("condition")
        if not isinstance(condition, dict) or not condition:
            raise PolicyError(f"Rule '{rule['id']}' must have a non-empty 'condition'.")
        unknown = set(condition) - _CONDITION_KEYS
        if unknown:
            raise PolicyError(
                f"Rule '{rule['id']}' has unknown condition keys: {sorted(unknown)}."
            )
    return data


def _as_set(value: Any) -> set[str]:
    if isinstance(value, list | tuple | set):
        return {str(v).lower() for v in value}
    return {str(value).lower()}


def _matches_path(path: str, patterns: Any) -> bool:
    path = (path or "").lower()
    for pattern in _as_set(patterns):
        if any(c in pattern for c in "*?[") and fnmatch.fnmatch(path, pattern):
            return True
        if pattern in path:
            return True
    return False


def _finding_matches(finding: dict[str, Any], condition: dict[str, Any]) -> bool:
    if "severity" in condition and str(finding.get("severity", "")).lower() not in _as_set(
        condition["severity"]
    ):
        return False
    if "rule_id" in condition and str(finding.get("rule_id", "")).lower() not in _as_set(
        condition["rule_id"]
    ):
        return False
    if "scanner" in condition and str(finding.get("scanner", "")).lower() not in _as_set(
        condition["scanner"]
    ):
        return False
    if "category" in condition and str(finding.get("category", "")).lower() not in _as_set(
        condition["category"]
    ):
        return False
    if "confidence" in condition and str(finding.get("confidence", "")).lower() not in _as_set(
        condition["confidence"]
    ):
        return False
    if "min_risk_score" in condition:
        try:
            if int(finding.get("risk_score", 0)) < int(condition["min_risk_score"]):
                return False
        except (TypeError, ValueError):
            return False
    if "is_new" in condition and bool(finding.get("is_new", False)) is not bool(
        condition["is_new"]
    ):
        return False
    return not (
        "path" in condition
        and not _matches_path(str(finding.get("file", "")), condition["path"])
    )


def evaluate(
    policy: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    environment: str | None = None,
) -> PolicyResult:
    """Evaluate a parsed policy against findings, returning a PolicyResult."""
    rule_results: list[RuleResult] = []
    violations: list[dict[str, Any]] = []
    status = STATUS_PASS

    for rule in policy.get("rules", []):
        condition = dict(rule.get("condition", {}))
        # Environment scoping: a rule with an `environment` condition only applies
        # when the evaluation environment matches.
        if "environment" in condition:
            envs = _as_set(condition.pop("environment"))
            if (environment or "").lower() not in envs:
                rule_results.append(
                    RuleResult(id=rule["id"], action=rule["action"], matched=0, passed=True)
                )
                continue

        matched = [f for f in findings if _finding_matches(f, condition)]
        action = rule["action"]
        rule_results.append(
            RuleResult(
                id=rule["id"],
                action=action,
                matched=len(matched),
                passed=not (bool(matched) and action == "fail"),
                sample=[str(f.get("rule_id", "")) for f in matched[:5]],
            )
        )
        if matched and action == "fail":
            status = STATUS_FAIL
            violations.append(
                {
                    "rule_id": rule["id"],
                    "action": action,
                    "matched": len(matched),
                    "findings": [str(f.get("rule_id", "")) for f in matched[:10]],
                }
            )
        elif matched and action == "warn" and status != STATUS_FAIL:
            status = STATUS_WARN
            violations.append(
                {
                    "rule_id": rule["id"],
                    "action": action,
                    "matched": len(matched),
                    "findings": [str(f.get("rule_id", "")) for f in matched[:10]],
                }
            )

    return PolicyResult(status=status, rules=rule_results, violations=violations)
