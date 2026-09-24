"""Tests for the deterministic configuration-file rule engine."""

from __future__ import annotations

from scanners.config.scanner import ConfigScanner


def _rule_ids(text: str) -> set[str]:
    return {f.rule_id for f in ConfigScanner().analyze_text(text, "config/app.yaml")}


def _findings(text: str):
    return ConfigScanner().analyze_text(text, "config/app.yaml")


VULNERABLE = """\
debug: true
ssl_verify: false
insecure_skip_verify: true
ssl_protocols: TLSv1 TLSv1.1
access-control-allow-origin: "*"
authentication: none
"""


def test_vulnerable_config_triggers_expected_rules() -> None:
    assert _rule_ids(VULNERABLE) == {"CFG001", "CFG002", "CFG003", "CFG004", "CFG005"}


CLEAN = """\
debug: false
ssl_verify: true
insecure_skip_verify: false
ssl_protocols: TLSv1.2 TLSv1.3
access-control-allow-origin: https://app.example.com
authentication: required
"""


def test_clean_config_has_no_findings() -> None:
    assert _findings(CLEAN) == []


def test_debug_across_formats() -> None:
    assert "CFG001" in _rule_ids("DEBUG=true\n")  # env
    assert "CFG001" in _rule_ids('"debug": true,\n')  # json
    assert "CFG001" in _rule_ids("debug = true\n")  # ini/toml
    assert "CFG001" in _rule_ids("app.debug: true\n")  # namespaced key
    assert "CFG001" not in _rule_ids("debug: false\n")


def test_tls_verification_disabled_polarity() -> None:
    assert "CFG002" in _rule_ids("verify: false\n")
    assert "CFG002" in _rule_ids("rejectUnauthorized: false\n")
    assert "CFG002" in _rule_ids("insecure: true\n")
    assert "CFG002" in _rule_ids("NODE_TLS_REJECT_UNAUTHORIZED=0\n")
    assert "CFG002" not in _rule_ids("verify: true\n")


def test_weak_tls_protocol() -> None:
    assert "CFG003" in _rule_ids("min_version: TLSv1\n")
    assert "CFG003" in _rule_ids("protocols: SSLv3\n")
    assert "CFG003" not in _rule_ids("min_version: TLSv1.2\n")


def test_permissive_cors() -> None:
    assert "CFG004" in _rule_ids('allow_origins: ["*"]\n')
    assert "CFG004" in _rule_ids("Access-Control-Allow-Origin: *\n")
    assert "CFG004" not in _rule_ids("allowed_origins: https://app.example.com\n")


def test_auth_disabled() -> None:
    assert "CFG005" in _rule_ids("auth: false\n")
    assert "CFG005" in _rule_ids("security_enabled: false\n")
    assert "CFG005" not in _rule_ids("auth: true\n")


def test_comments_are_ignored() -> None:
    assert _findings("# debug: true\n") == []
    assert _findings("// ssl_verify: false\n") == []
    assert _findings("; auth: false\n") == []


def test_findings_carry_full_schema() -> None:
    finding = next(f for f in _findings(VULNERABLE) if f.rule_id == "CFG002")
    assert finding.scanner == "config-rules"
    assert finding.title and finding.description and finding.recommendation
    assert finding.line_number is not None
    assert finding.category is not None and finding.confidence is not None
