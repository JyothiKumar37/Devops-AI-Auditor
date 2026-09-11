"""Tests for individual secret detectors."""

from __future__ import annotations

import pytest

from scanners.secrets.scanner import SecretScanner


def _ids(text: str) -> set[str]:
    return {f.rule_id for f in SecretScanner().scan_text("f.txt", text)}


@pytest.mark.parametrize(
    ("text", "rule_id"),
    [
        ('key = "AKIAIOSFODNN7EXAMPLE"', "SEC001"),
        ('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', "SEC002"),
        # Provider tokens are split into adjacent string literals (Python joins
        # them at runtime) so this test file contains no contiguous real-format
        # token that would trip GitHub push protection, while still exercising
        # the detectors with the full reconstructed value.
        ("token: ghp_1234567890abcdef" "ghijklmnopqrstuvwxyz", "SEC003"),
        ('google = "AIza' + "a" * 35 + '"', "SEC004"),
        ("slack = xoxb-1234567890-" "abcdefABCDEF12", "SEC005"),
        ("stripe = sk_live_0123456789" "abcdefABCDEF", "SEC006"),
        ("DB = postgres://user:SecretPass99@db:5432/app", "SEC009"),
    ],
)
def test_typed_detectors(text: str, rule_id: str) -> None:
    assert rule_id in _ids(text)


def test_jwt_detection() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij"
    assert "SEC008" in _ids(f"token = {jwt}")


def test_generic_credential() -> None:
    assert "SEC010" in _ids('password = "realL00kingSecretValue"')


def test_placeholders_are_ignored() -> None:
    assert _ids('password = "changeme"') == set()
    assert _ids('password = "your_password_here"') == set()
    assert _ids('api_key = "${API_KEY}"') == set()
    assert _ids('token = "$MY_TOKEN"') == set()


def test_high_entropy_token() -> None:
    token = "b3J8Kd9Xq2Lm5Pn7Rt1Vw4Zy6Ac0Eg8Ij"
    assert "SEC011" in _ids(f'session = "{token}"')


def test_hex_checksums_are_not_high_entropy_secrets() -> None:
    sha = "a" * 40  # a git SHA / checksum shape
    assert "SEC011" not in _ids(f'rev = "{sha}"')
