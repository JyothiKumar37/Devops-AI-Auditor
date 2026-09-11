"""Tests for the Terraform parser and line index."""

from __future__ import annotations

from scanners.terraform.parser import LineIndex, TerraformSyntaxError, parse_hcl

CONFIG = """\
resource "aws_s3_bucket" "data" {
  bucket = "data"
  acl    = "private"
}

variable "region" {
  type    = string
  default = "us-east-1"
}
"""


def test_parse_and_block_lines() -> None:
    parsed = parse_hcl(CONFIG)
    assert "resource" in parsed
    index = LineIndex(CONFIG)
    assert index.block_line("resource", "aws_s3_bucket", "data") == 1
    assert index.block_line("variable", "region") == 6


def test_attr_line() -> None:
    index = LineIndex(CONFIG)
    rng = index.block_range("resource", "aws_s3_bucket", "data")
    assert rng is not None
    assert index.attr_line(rng[0], rng[1], "acl") == 3


def test_brace_on_next_line() -> None:
    text = 'resource "aws_vpc" "main"\n{\n  cidr_block = "10.0.0.0/16"\n}\n'
    index = LineIndex(text)
    assert index.block_line("resource", "aws_vpc", "main") == 1


def test_invalid_hcl_raises() -> None:
    try:
        parse_hcl('resource "aws_s3_bucket" "x" { acl = }\n')
    except TerraformSyntaxError:
        return
    raise AssertionError("expected TerraformSyntaxError")
