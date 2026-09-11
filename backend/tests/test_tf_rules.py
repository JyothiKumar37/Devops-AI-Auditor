"""Tests for the deterministic Terraform rule engine."""

from __future__ import annotations

from models.enums import Severity
from scanners.terraform import TerraformScanner


def _ids(text: str) -> set[str]:
    return {f.rule_id for f in TerraformScanner().analyze_files([("main.tf", text)])}


def _findings(text: str):
    return TerraformScanner().analyze_files([("main.tf", text)])


SSH_OPEN = """\
resource "aws_security_group" "web" {
  name = "web"
  tags = { Name = "web" }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


def test_unrestricted_ssh() -> None:
    findings = [f for f in _findings(SSH_OPEN) if f.rule_id == "TF002"]
    assert findings and findings[0].severity == Severity.CRITICAL


def test_unrestricted_database_port() -> None:
    text = SSH_OPEN.replace("from_port   = 22", "from_port   = 3306").replace(
        "to_port     = 22", "to_port     = 3306"
    )
    assert "TF003" in _ids(text)


def test_open_http_is_generic_open() -> None:
    text = SSH_OPEN.replace("from_port   = 22", "from_port   = 8080").replace(
        "to_port     = 22", "to_port     = 8080"
    )
    ids = _ids(text)
    assert "TF001" in ids
    assert "TF002" not in ids


def test_public_rds_and_unencrypted_and_backups() -> None:
    text = """\
resource "aws_db_instance" "main" {
  engine                  = "mysql"
  publicly_accessible     = true
  backup_retention_period = 0
  tags                    = { Name = "db" }
}
"""
    ids = _ids(text)
    assert {"TF004", "TF006", "TF010"} <= ids


def test_public_s3() -> None:
    text = """\
resource "aws_s3_bucket" "d" {
  bucket = "d"
  acl    = "public-read"
  tags   = { a = "b" }
}
"""
    assert "TF005" in _ids(text)


def test_unencrypted_ebs() -> None:
    text = """\
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 8
  tags              = { a = "b" }
}
"""
    assert "TF006" in _ids(text)


def test_wildcard_iam_policy() -> None:
    text = """\
resource "aws_iam_role_policy" "admin" {
  name = "admin"
  role = "some-role"
  policy = <<EOF
{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
EOF
}
"""
    findings = [f for f in _findings(text) if f.rule_id == "TF007"]
    assert findings


def test_hardcoded_secret_attribute_is_redacted() -> None:
    text = """\
resource "aws_db_instance" "m" {
  engine            = "mysql"
  password          = "literalpass123"
  storage_encrypted = true
  tags              = { a = "b" }
}
"""
    secret = next(f for f in _findings(text) if f.rule_id == "TF008")
    assert secret.severity == Severity.CRITICAL
    assert "literalpass123" not in (secret.evidence or "")


def test_aws_access_key_in_provider() -> None:
    text = 'provider "aws" {\n  region = "us-east-1"\n  access_key = "AKIAIOSFODNN7EXAMPLE"\n}\n'
    assert "TF008" in _ids(text)


def test_missing_tags() -> None:
    text = """\
resource "aws_instance" "web" {
  ami           = "ami-123"
  instance_type = "t3.micro"
}
"""
    assert "TF020" in _ids(text)


def test_missing_tags_not_flagged_when_present() -> None:
    text = """\
resource "aws_instance" "web" {
  ami           = "ami-123"
  instance_type = "t3.micro"
  tags          = { Name = "web" }
}
"""
    assert "TF020" not in _ids(text)


# --- contextual reasoning ---------------------------------------------------


def _db(name: str, environment: str, extra: str = "") -> str:
    return (
        f'resource "aws_db_instance" "{name}" {{\n'
        '  engine            = "mysql"\n'
        "  storage_encrypted = true\n"
        f"{extra}"
        f'  tags              = {{ Environment = "{environment}" }}\n'
        "}\n"
    )


def test_multi_az_not_flagged_for_non_production() -> None:
    assert "TF012" not in _ids(_db("dev", "dev"))


def test_multi_az_flagged_for_production_context() -> None:
    assert "TF012" in _ids(_db("prod_db", "production", extra="  multi_az = false\n"))


def test_deletion_protection_only_for_production() -> None:
    assert "TF011" not in _ids(_db("dev", "dev"))
    assert "TF011" in _ids(_db("prod", "prod"))
