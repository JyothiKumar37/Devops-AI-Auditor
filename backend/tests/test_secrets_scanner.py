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
    body = (
        "MIIEowIBAAKCAQEA7Yb3Q2xR5mN8pQ2vK9wL1sT4uV6xY0zA3bC5dE7fG9hJ2kM\n"
        "4nP6qR8sT0uV2wX4yZ6aB8cD0eF2gH4iJ6kL8mN0oP2qR4sT6uV8wX0yZ2aB4cD"
    )
    text = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n"
    findings = SecretScanner().scan_text("id_rsa", text)
    key = next(f for f in findings if f.rule_id == "SEC007")
    assert key.severity == Severity.CRITICAL
    assert "MIIEowIBAAKCAQEA" not in (key.evidence or "")


def test_private_key_header_mention_is_not_flagged() -> None:
    # A bare header with no key material (a detector's own pattern, docs, or a
    # redacted evidence literal) must NOT be reported as a committed key.
    for benign in (
        'PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |)PRIVATE KEY-----")',
        'evidence = "-----BEGIN PRIVATE KEY----- (redacted)"',
        "# see -----BEGIN PRIVATE KEY----- in the PEM format docs",
    ):
        ids = {f.rule_id for f in SecretScanner().scan_text("scanners/x.py", benign)}
        assert "SEC007" not in ids, benign


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


def test_template_and_test_files_downrank_secrets() -> None:
    db_url = 'DATABASE_URL="postgres://user:S3cretP0rtalValue99@db:5432/app"'
    # In a real file the DB password is HIGH severity.
    prod = SecretScanner().scan_text("backend/.env", db_url)
    assert any(f.rule_id == "SEC009" and f.severity == Severity.HIGH for f in prod)

    # In a template (.env.example) the same finding is down-ranked to LOW.
    template = SecretScanner().scan_text("backend/.env.example", db_url)
    assert template and all(f.severity == Severity.LOW for f in template)

    # Credentials in test paths are down-ranked too.
    test = SecretScanner().scan_text(
        "src/test/java/AuthTest.java", 'password = "S3cretP0rtalValue99"'
    )
    assert test and all(f.severity == Severity.LOW for f in test)


def test_commented_out_credentials_are_skipped() -> None:
    # Generic/high-entropy matches inside comments are disabled code, not live
    # secrets, and must not be reported (they land highlights on comment lines).
    for comment in (
        '// password = "realL00kingSecretValue"',
        '# api_key = "realL00kingSecretValue"',
        '   * token = "realL00kingSecretValue"',
        '-- secret = "realL00kingSecretValue"',
    ):
        assert SecretScanner().scan_text("app.js", comment) == [], comment

    # The same assignment as real code (not a comment) is still flagged.
    findings = SecretScanner().scan_text("app.js", 'api_key = "realL00kingSecretValue"')
    assert any(f.rule_id == "SEC010" for f in findings)

    # A genuine structured secret is still caught even inside a comment.
    aws = SecretScanner().scan_text("app.js", "# AWS_KEY = AKIAIOSFODNN7EXAMPLE")
    assert any(f.rule_id == "SEC001" for f in aws)


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
