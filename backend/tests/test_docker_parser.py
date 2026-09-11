"""Tests for the Dockerfile parser."""

from __future__ import annotations

from scanners.docker.parser import parse_dockerfile


def test_parses_instructions_with_line_numbers() -> None:
    df = parse_dockerfile("# comment\nFROM alpine:3.19\nUSER app\n")
    cmds = [(i.cmd, i.line) for i in df.instructions]
    assert cmds == [("FROM", 2), ("USER", 3)]


def test_joins_line_continuations() -> None:
    text = "FROM alpine:3.19\nRUN apt-get update \\\n    && apt-get install -y curl\n"
    df = parse_dockerfile(text)
    run = df.by_cmd("RUN")[0]
    assert run.line == 2
    assert "apt-get update" in run.value
    assert "apt-get install -y curl" in run.value


def test_multi_stage_indices_and_aliases() -> None:
    text = (
        "FROM golang:1.22 AS build\n"
        "RUN go build -o app\n"
        "FROM gcr.io/distroless/base\n"
        "COPY --from=build /app /app\n"
    )
    df = parse_dockerfile(text)
    assert df.stage_count == 2
    assert df.stage_aliases == frozenset({"build"})
    assert df.froms[0].stage_index == 0
    assert df.froms[1].stage_index == 1


def test_parses_from_tag_digest_alias() -> None:
    df = parse_dockerfile("FROM python:3.11-slim@sha256:abc AS base\n")
    from_image = df.froms[0]
    assert from_image.image == "python"
    assert from_image.tag == "3.11-slim"
    assert from_image.digest == "sha256:abc"
    assert from_image.alias == "base"


def test_from_with_platform_flag() -> None:
    df = parse_dockerfile("FROM --platform=linux/amd64 ubuntu:22.04\n")
    assert df.froms[0].image == "ubuntu"
    assert df.froms[0].tag == "22.04"
