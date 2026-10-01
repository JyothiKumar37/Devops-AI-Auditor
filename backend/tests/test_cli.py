"""Tests for the devops-auditor CLI (scan/policy/sbom, exit codes, formats)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import cli

VULN_DOCKERFILE = "FROM ubuntu:latest\nUSER root\n"
CLEAN_DOCKERFILE = "FROM ubuntu:24.04\nUSER 1000\n"
POLICY_FAIL = """\
version: 1
name: strict
rules:
  - id: no-root
    condition:
      rule_id: DCK003
    action: fail
"""


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


def test_scan_clean_dir_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    _write(tmp_path, {"Dockerfile": CLEAN_DOCKERFILE})
    code = cli.main(["scan", str(tmp_path)])
    assert code == 0
    assert "DevOps AI Auditor" in capsys.readouterr().out


def test_scan_vulnerable_dir_fails(tmp_path: Path) -> None:
    _write(tmp_path, {"Dockerfile": VULN_DOCKERFILE})
    # USER root is a high finding -> default --fail-on high -> exit 1.
    assert cli.main(["scan", str(tmp_path)]) == 1


def test_scan_fail_on_critical_allows_high(tmp_path: Path) -> None:
    _write(tmp_path, {"Dockerfile": VULN_DOCKERFILE})
    # Raising the threshold to critical lets a high finding pass.
    assert cli.main(["scan", str(tmp_path), "--fail-on", "critical"]) == 0


def test_scan_json_format(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    _write(tmp_path, {"Dockerfile": VULN_DOCKERFILE})
    cli.main(["scan", str(tmp_path), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert "findings" in data and "gate" in data
    assert any(f["rule_id"].startswith("DCK") for f in data["findings"])


def test_scan_sarif_format(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    _write(tmp_path, {"Dockerfile": VULN_DOCKERFILE})
    cli.main(["scan", str(tmp_path), "--format", "sarif"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "DevOps AI Auditor"


def test_scan_output_to_file(tmp_path: Path) -> None:
    _write(tmp_path, {"Dockerfile": VULN_DOCKERFILE})
    out = tmp_path / "r.sarif"
    cli.main(["scan", str(tmp_path), "--format", "sarif", "--output", str(out)])
    assert out.exists() and json.loads(out.read_text())["version"] == "2.1.0"


def test_scan_missing_dir_is_runtime_error() -> None:
    assert cli.main(["scan", "/no/such/dir/xyz"]) == 2


def test_policy_check_fail(tmp_path: Path) -> None:
    _write(tmp_path, {"Dockerfile": VULN_DOCKERFILE})
    policy = tmp_path / "p.yaml"
    policy.write_text(POLICY_FAIL)
    assert cli.main(["policy", "check", str(tmp_path), "--policy", str(policy)]) == 1


def test_policy_check_invalid_policy_is_error(tmp_path: Path) -> None:
    _write(tmp_path, {"Dockerfile": VULN_DOCKERFILE})
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: x\nrules: []")
    code = cli.main(["policy", "check", str(tmp_path), "--policy", str(bad)])
    assert code == 2


def test_sbom_command(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    _write(tmp_path, {"requirements.txt": "flask==2.3.0\n"})
    assert cli.main(["sbom", str(tmp_path)]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["bomFormat"] == "CycloneDX"
    assert any(c["name"] == "flask" for c in doc["components"])


def test_check_alias_scans_path(tmp_path: Path) -> None:
    _write(tmp_path, {"Dockerfile": CLEAN_DOCKERFILE})
    assert cli.main(["check", str(tmp_path)]) == 0
