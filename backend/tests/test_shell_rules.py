"""Tests for the deterministic shell-script rule engine."""

from __future__ import annotations

from models.enums import Severity
from scanners.shell.scanner import ShellScanner


def _rule_ids(text: str) -> set[str]:
    return {f.rule_id for f in ShellScanner().analyze_text(text, "deploy.sh")}


def _findings(text: str):
    return ShellScanner().analyze_text(text, "deploy.sh")


VULNERABLE = """\
#!/bin/bash
curl -fsSL https://example.com/install.sh | bash
eval "$USER_INPUT"
rm -rf $BUILD_DIR
chmod 777 /opt/app
wget --no-check-certificate https://example.com/file
sudo systemctl restart nginx
"""


def test_vulnerable_script_triggers_expected_rules() -> None:
    ids = _rule_ids(VULNERABLE)
    expected = {"SH002", "SH003", "SH004", "SH005", "SH006", "SH007", "SH008"}
    assert ids == expected
    # Shebang is present, so the missing-shebang rule must NOT fire.
    assert "SH001" not in ids


CLEAN = """\
#!/usr/bin/env bash
set -euo pipefail

rm -rf ./build
chmod 640 config.conf
curl -fsSL https://example.com/file -o /tmp/file
"""


def test_clean_script_has_no_findings() -> None:
    assert _findings(CLEAN) == []


def test_missing_shebang() -> None:
    assert "SH001" in _rule_ids("echo hello\n")


def test_shebang_present_suppresses_sh001() -> None:
    assert "SH001" not in _rule_ids("#!/bin/sh\nset -e\necho hi\n")


def test_missing_errexit_flagged() -> None:
    assert "SH002" in _rule_ids("#!/bin/bash\necho hi\n")


def test_errexit_variants_suppress_sh002() -> None:
    assert "SH002" not in _rule_ids("#!/bin/bash\nset -euo pipefail\necho hi\n")
    assert "SH002" not in _rule_ids("#!/bin/bash\nset -o errexit\necho hi\n")


def test_pipe_to_shell_detected() -> None:
    assert "SH003" in _rule_ids("curl https://x | sh\n")
    assert "SH003" in _rule_ids("wget -qO- https://x | sudo bash\n")


def test_pipe_to_non_shell_is_clean() -> None:
    assert "SH003" not in _rule_ids("curl https://x | grep something\n")


def test_eval_detected_but_not_substrings() -> None:
    assert "SH004" in _rule_ids('eval "$cmd"\n')
    # `retrieval` contains "eval" but must not be flagged.
    assert "SH004" not in _rule_ids("retrieval_count=5\n")


def test_dangerous_rm_targets() -> None:
    assert "SH005" in _rule_ids("rm -rf $BUILD_DIR\n")
    assert "SH005" in _rule_ids('rm -rf "${WORKDIR}"\n')
    assert "SH005" in _rule_ids("rm -rf /var/lib/data\n")


def test_safe_rm_is_clean() -> None:
    assert "SH005" not in _rule_ids("rm -rf ./build\n")
    assert "SH005" not in _rule_ids("rm file.txt\n")


def test_chmod_777_detected() -> None:
    assert "SH006" in _rule_ids("chmod 777 /opt/app\n")
    assert "SH006" in _rule_ids("chmod -R 777 .\n")
    assert "SH006" not in _rule_ids("chmod 640 config.conf\n")


def test_insecure_download_detected() -> None:
    assert "SH007" in _rule_ids("curl -k https://example.com\n")
    assert "SH007" in _rule_ids("curl --insecure https://example.com\n")
    assert "SH007" in _rule_ids("wget --no-check-certificate https://example.com\n")
    assert "SH007" not in _rule_ids("curl -fsSL https://example.com\n")


def test_sudo_detected_but_not_in_comments() -> None:
    assert "SH008" in _rule_ids("sudo apt-get install -y curl\n")
    assert "SH008" not in _rule_ids("# use sudo to install\n")


def test_findings_carry_full_schema() -> None:
    finding = next(f for f in _findings(VULNERABLE) if f.rule_id == "SH003")
    assert finding.scanner == "shell-rules"
    assert finding.severity == Severity.HIGH
    assert finding.title and finding.description and finding.recommendation
    assert finding.line_number is not None
    assert finding.category is not None and finding.confidence is not None
