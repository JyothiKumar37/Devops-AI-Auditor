"""Tests for the Gitleaks adapter (masking of reported secrets)."""

from __future__ import annotations

import json

from scanners.secrets import gitleaks


def test_gitleaks_output_is_masked() -> None:
    raw = "AKIAIOSFODNN7EXAMPLE"
    output = json.dumps(
        [
            {
                "Description": "AWS Access Key",
                "File": "./config/prod.env",
                "StartLine": 12,
                "RuleID": "aws-access-token",
                "Secret": raw,
                "Match": f"key={raw}",
            }
        ]
    )
    findings = gitleaks.parse_gitleaks_json(output)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.scanner == "gitleaks"
    assert finding.line_number == 12
    assert finding.file_path == "config/prod.env"
    # The raw secret must never survive parsing.
    assert raw not in (finding.evidence or "")
    assert finding.evidence and "*" in finding.evidence


def test_gitleaks_empty_and_invalid() -> None:
    assert gitleaks.parse_gitleaks_json("") == []
    assert gitleaks.parse_gitleaks_json("not json") == []


def test_gitleaks_availability_is_bool() -> None:
    assert isinstance(gitleaks.is_available(), bool)
