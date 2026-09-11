"""Tests for the optional Terraform tool adapters (no binaries required)."""

from __future__ import annotations

import json

from models.enums import Severity
from scanners.terraform import tools


def test_fmt_output_parsing() -> None:
    findings = tools.parse_fmt_output("main.tf\nmodules/vpc/main.tf\n")
    assert len(findings) == 2
    assert findings[0].scanner == "terraform"
    assert findings[0].file_path == "main.tf"


def test_validate_json_parsing() -> None:
    output = json.dumps(
        {
            "valid": False,
            "diagnostics": [
                {
                    "severity": "error",
                    "summary": "Reference to undeclared resource",
                    "detail": "d",
                    "range": {"filename": "main.tf", "start": {"line": 12}},
                }
            ],
        }
    )
    findings = tools.parse_validate_json(output)
    assert findings[0].severity == Severity.HIGH
    assert findings[0].line_number == 12


def test_tflint_json_parsing() -> None:
    output = json.dumps(
        {
            "issues": [
                {
                    "rule": {"name": "terraform_unused_declarations", "severity": "warning"},
                    "message": "variable is declared but not used",
                    "range": {"filename": "main.tf", "start": {"line": 3}},
                }
            ]
        }
    )
    findings = tools.parse_tflint_json(output)
    assert findings[0].scanner == "tflint"
    assert findings[0].rule_id == "terraform_unused_declarations"
    assert findings[0].severity == Severity.MEDIUM


def test_checkov_json_parsing() -> None:
    output = json.dumps(
        {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "check_name": "S3 Bucket has an ACL defined which allows public access",
                        "severity": "HIGH",
                        "file_path": "/main.tf",
                        "file_line_range": [10, 20],
                    }
                ]
            }
        }
    )
    findings = tools.parse_checkov_json(output)
    assert findings[0].scanner == "checkov"
    assert findings[0].rule_id == "CKV_AWS_20"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].file_path == "main.tf"
    assert findings[0].line_number == 10


def test_parsers_handle_empty_and_invalid() -> None:
    assert tools.parse_tflint_json("") == []
    assert tools.parse_checkov_json("not json") == []
    assert tools.parse_validate_json("") == []


def test_availability_checks_do_not_raise() -> None:
    for check in (tools.terraform_available, tools.tflint_available, tools.checkov_available):
        assert isinstance(check(), bool)
