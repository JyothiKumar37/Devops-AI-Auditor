"""SARIF 2.1.0 rendering of the report model.

Produces a Static Analysis Results Interchange Format document so findings can be
consumed by CI systems and code-scanning dashboards (notably GitHub code
scanning). One SARIF rule is emitted per distinct scanner rule; each finding
becomes a result that references its rule and physical location.

Suppressed (baselined) findings are already excluded from the report model, so
the SARIF reflects the repository's active posture - safe to gate CI on.
"""

from __future__ import annotations

import json
from typing import Any

from services.fingerprint import finding_fingerprint
from services.report.model import ReportFinding, ReportModel

_TOOL_NAME = "DevOps AI Auditor"
_TOOL_URI = "https://github.com/devops-ai-auditor/devops-ai-auditor"
_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Finding severity -> SARIF result level.
_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
# Finding severity -> GitHub code-scanning "security-severity" (CVSS-like score).
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
}


def _level(severity: str) -> str:
    return _LEVEL.get(severity, "warning")


def _rule(finding: ReportFinding) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description or finding.title},
        "defaultConfiguration": {"level": _level(finding.severity)},
        "properties": {
            "category": finding.category,
            "tags": [finding.category, finding.scanner],
            "security-severity": _SECURITY_SEVERITY.get(finding.severity, "5.0"),
        },
    }
    if finding.recommendation:
        rule["help"] = {"text": finding.recommendation}
    return rule


def _result(finding: ReportFinding, rule_index: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _level(finding.severity),
        "message": {"text": finding.title},
        "properties": {
            "severity": finding.severity,
            "confidence": finding.confidence,
            "scanner": finding.scanner,
        },
        "partialFingerprints": {
            "devopsAuditor/v1": finding_fingerprint(
                finding.rule_id, finding.file, finding.evidence
            )
        },
    }
    if finding.file:
        physical: dict[str, Any] = {"artifactLocation": {"uri": finding.file}}
        if finding.line and finding.line > 0:
            physical["region"] = {"startLine": finding.line}
        result["locations"] = [{"physicalLocation": physical}]
    return result


def render_sarif(model: ReportModel, *, tool_version: str = "0.1.0") -> bytes:
    """Serialize the report model to a SARIF 2.1.0 document (bytes)."""
    findings = model.detailed_findings

    # One rule per distinct rule_id; the first finding defines its metadata.
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    for finding in findings:
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rules)
            rules.append(_rule(finding))

    results = [_result(f, rule_index[f.rule_id]) for f in findings]

    document: dict[str, Any] = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "informationUri": _TOOL_URI,
                        "version": tool_version,
                        "rules": rules,
                    }
                },
                "automationDetails": {
                    "id": f"{model.repository.name}/{model.repository.scan_id}"
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8")
