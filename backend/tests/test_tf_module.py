"""Tests for module-level Terraform analysis (references, unused vars, deps)."""

from __future__ import annotations

from scanners.terraform import TerraformScanner


def _ids(*files: tuple[str, str]) -> set[str]:
    return {f.rule_id for f in TerraformScanner().analyze_files(list(files))}


def _bucket(body: str) -> str:
    return f'resource "aws_s3_bucket" "b" {{\n{body}  tags   = {{ a = "b" }}\n}}\n'


def test_undefined_variable_reference() -> None:
    text = _bucket("  bucket = var.does_not_exist\n")
    assert "TF021" in _ids(("main.tf", text))


def test_defined_variable_reference_is_clean() -> None:
    text = 'variable "name" {\n  type = string\n}\n' + _bucket("  bucket = var.name\n")
    assert "TF021" not in _ids(("main.tf", text))


def test_cross_file_variable_usage() -> None:
    variables = 'variable "bucket_name" {\n  type = string\n}\n'
    resource = _bucket("  bucket = var.bucket_name\n")
    # Declared in one file, used in another within the same directory: not unused.
    ids = _ids(("variables.tf", variables), ("main.tf", resource))
    assert "TF022" not in ids


def test_unused_variable() -> None:
    text = 'variable "unused" {\n  type = string\n}\n'
    assert "TF022" in _ids(("variables.tf", text))


def test_variable_missing_type() -> None:
    text = 'variable "no_type" {\n  default = "x"\n}\n'
    # Referenced so it is not "unused", but missing a type constraint.
    resource = 'resource "aws_s3_bucket" "b" {\n  bucket = var.no_type\n  tags = { a = "b" }\n}\n'
    assert "TF023" in _ids(("v.tf", text), ("m.tf", resource))


def test_sensitive_variable_not_marked_sensitive() -> None:
    text = 'variable "db_password" {\n  type = string\n}\n'
    resource = """\
resource "aws_db_instance" "d" {
  engine            = "mysql"
  password          = var.db_password
  storage_encrypted = true
  tags              = { a = "b" }
}
"""
    assert "TF024" in _ids(("v.tf", text), ("m.tf", resource))


def test_bad_depends_on() -> None:
    text = (
        'resource "aws_s3_bucket" "a" {\n  bucket = "a"\n  tags = { a = "b" }\n}\n'
        'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n  tags = { a = "b" }\n'
        "  depends_on = [aws_s3_bucket.ghost]\n}\n"
    )
    assert "TF025" in _ids(("main.tf", text))


CLEAN = """\
variable "bucket_name" {
  type = string
}

resource "aws_s3_bucket" "data" {
  bucket = var.bucket_name
  acl    = "private"
  tags = {
    Name = "data"
  }
}

resource "aws_security_group" "web" {
  name = "web"
  tags = { Name = "web" }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
"""


def test_clean_configuration_has_no_findings() -> None:
    findings = TerraformScanner().analyze_files([("main.tf", CLEAN)])
    assert findings == [], [f"{f.rule_id}:{f.title}" for f in findings]
