"""Tests for the optional Kubernetes tool adapters (no binaries required)."""

from __future__ import annotations

import json

from models.enums import Severity
from scanners.kubernetes import tools


def test_kubeconform_parsing() -> None:
    output = json.dumps(
        {
            "resources": [
                {"kind": "Deployment", "status": "statusValid", "msg": ""},
                {"kind": "Service", "status": "statusInvalid", "msg": "missing required field"},
            ]
        }
    )
    findings = tools.parse_kubeconform_json(output, "svc.yaml")
    assert len(findings) == 1
    assert findings[0].scanner == "kubeconform"
    assert findings[0].severity == Severity.HIGH


def test_kubeconform_empty_and_invalid() -> None:
    assert tools.parse_kubeconform_json("", "x.yaml") == []
    assert tools.parse_kubeconform_json("not json", "x.yaml") == []


def test_kubelinter_parsing() -> None:
    output = json.dumps(
        {
            "Reports": [
                {
                    "Check": "no-read-only-root-fs",
                    "Diagnostic": {"Message": "container is not read-only"},
                    "Object": {"Metadata": {"FilePath": "deploy.yaml"}},
                }
            ]
        }
    )
    findings = tools.parse_kubelinter_json(output)
    assert len(findings) == 1
    assert findings[0].scanner == "kube-linter"
    assert findings[0].rule_id == "no-read-only-root-fs"
    assert findings[0].file_path == "deploy.yaml"


def test_trivy_config_parsing() -> None:
    output = json.dumps(
        {
            "Results": [
                {
                    "Target": "deploy.yaml",
                    "Misconfigurations": [
                        {
                            "ID": "KSV001",
                            "Title": "Privileged container",
                            "Severity": "HIGH",
                            "Description": "d",
                            "Resolution": "r",
                        }
                    ],
                }
            ]
        }
    )
    findings = tools.parse_trivy_config_json(output)
    assert len(findings) == 1
    assert findings[0].rule_id == "KSV001"
    assert findings[0].severity == Severity.HIGH


def test_availability_checks_do_not_raise() -> None:
    # These return booleans regardless of whether the binaries are installed.
    assert isinstance(tools.kubeconform_available(), bool)
    assert isinstance(tools.kubelinter_available(), bool)
    assert isinstance(tools.trivy_available(), bool)
