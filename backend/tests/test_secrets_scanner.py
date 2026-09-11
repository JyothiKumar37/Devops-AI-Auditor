"""Tests for the SecretScanner (masking guarantees, dedupe, tree scanning)."""

from __future__ import annotations

from pathlib import Path

from models.enums import Severity
from scanners.secrets.scanner import SecretScanner

# Real-format (but non-production) secrets used to prove they are never leaked.
# The GitHub-token literal is split into adjacent string literals (joined at
# runtime) so no contiguous real-format token is committed - this keeps the
# fixture realistic for the scanner without tripping GitHub push protection.
RAW_SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_1234567890abcdef" "ghijklmnopqrstuvwxyz",
    "SuperSecretDbPassword99",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
]

SAMPLE = f"""\
AWS_ACCESS_KEY_ID = "{RAW_SECRETS[0]}"
GITHUB_TOKEN={RAW_SECRETS[1]}
DATABASE_URL=postgres://admin:{RAW_SECRETS[2]}@db:5432/app
aws_secret_access_key = "{RAW_SECRETS[3]}"
"""


def test_no_raw_secret_ever_appears_in_findings() -> None:
    findings = SecretScanner().scan_text("config.env", SAMPLE)
    assert findings
    blob = " ".join(
        " ".join(str(x) for x in (f.evidence, f.description, f.title, f.recommendation))
        for f in findings
    )
    for raw in RAW_SECRETS:
        assert raw not in blob, f"raw secret leaked: {raw}"


def test_findings_have_required_fields() -> None:
    finding = SecretScanner().scan_text("config.env", SAMPLE)[0]
    assert finding.rule_id and finding.title  # secret type
    assert finding.file_path == "config.env"
    assert finding.line_number is not None
    assert finding.evidence  # masked evidence
    assert finding.severity is not None
    assert finding.recommendation


def test_private_key_detection_is_redacted() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabcdef...\n-----END RSA PRIVATE KEY-----\n"
    findings = SecretScanner().scan_text("id_rsa", text)
    key = next(f for f in findings if f.rule_id == "SEC007")
    assert key.severity == Severity.CRITICAL
    assert "MIIEabcdef" not in (key.evidence or "")


def test_duplicate_detectors_collapse_to_most_severe() -> None:
    # access_key assignment matches both the AWS pattern (SEC001) and the generic
    # credential rule (SEC010); the result is a single CRITICAL finding.
    findings = SecretScanner().scan_text("f.env", 'access_key = "AKIAIOSFODNN7EXAMPLE"')
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC001"


def test_lockfiles_skip_entropy_detector() -> None:
    token = "b3J8Kd9Xq2Lm5Pn7Rt1Vw4Zy6Ac0Eg8Ij"
    line = f'"integrity": "{token}"'
    assert SecretScanner().scan_text("package-lock.json", line) == []


def test_clean_file_has_no_findings() -> None:
    text = "name = \"my-app\"\nversion = \"1.2.3\"\ndebug = false\n"
    assert SecretScanner().scan_text("config.toml", text) == []


def test_analyze_repo_skips_binary_and_large_files(tmp_path: Path) -> None:
    (tmp_path / "app.env").write_text(f'token = "{RAW_SECRETS[1]}"\n')
    (tmp_path / "image.bin").write_bytes(b"\x00\x01secret AKIAIOSFODNN7EXAMPLE\x00")

    findings = SecretScanner().analyze_repo(tmp_path, ["app.env", "image.bin"])
    files = {f.file_path for f in findings}
    assert "app.env" in files
    assert "image.bin" not in files  # binary content is skipped
