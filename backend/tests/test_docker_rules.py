"""Tests for the deterministic Docker rule engine using vulnerable Dockerfiles."""

from __future__ import annotations

from models.enums import Severity
from scanners.docker.scanner import DockerScanner


def _rule_ids(text: str) -> set[str]:
    return {f.rule_id for f in DockerScanner().analyze_text(text, "Dockerfile")}


def _findings(text: str):
    return DockerScanner().analyze_text(text, "Dockerfile")


# Intentionally vulnerable Dockerfile exercising many rules at once.
VULNERABLE = """\
FROM ubuntu:latest
RUN apt-get update
RUN apt-get install -y curl python3
ENV DB_PASSWORD=hunter2plaintext
RUN curl http://example.com/install.sh | sh
ADD https://example.com/app.tar.gz /opt/app.tar.gz
COPY . .
EXPOSE 22
EXPOSE 8080
USER root
RUN chmod -R 777 /opt
CMD ["python3", "app.py"]
"""


def test_vulnerable_dockerfile_triggers_expected_rules() -> None:
    ids = _rule_ids(VULNERABLE)
    for expected in {
        "DCK001",  # latest tag
        "DCK003",  # USER root
        "DCK005",  # secret
        "DCK006",  # SSH port
        "DCK007",  # consecutive RUN
        "DCK008",  # apt cache
        "DCK010",  # COPY . .
        "DCK011",  # ADD url
        "DCK012",  # no healthcheck
        "DCK014",  # curl | sh + chmod 777
        "DCK015",  # no-install-recommends
    }:
        assert expected in ids, f"expected {expected} in {sorted(ids)}"


def test_latest_tag() -> None:
    assert "DCK001" in _rule_ids("FROM node:latest\nUSER node\n")


def test_unpinned_base_image() -> None:
    assert "DCK002" in _rule_ids("FROM ubuntu\nUSER app\n")


def test_pinned_image_is_clean() -> None:
    ids = _rule_ids("FROM alpine:3.19\nUSER app\nCMD [\"sh\"]\n")
    assert "DCK001" not in ids
    assert "DCK002" not in ids


def test_running_as_root() -> None:
    assert "DCK003" in _rule_ids("FROM alpine:3.19\nUSER root\n")


def test_missing_user() -> None:
    assert "DCK004" in _rule_ids("FROM alpine:3.19\nCMD [\"sh\"]\n")


def test_non_root_user_is_clean() -> None:
    ids = _rule_ids("FROM alpine:3.19\nUSER 1001\nCMD [\"sh\"]\n")
    assert "DCK003" not in ids
    assert "DCK004" not in ids


def test_secret_severity_is_high_or_critical() -> None:
    findings = [f for f in _findings("FROM alpine:3.19\nENV SECRET_TOKEN=abcd1234\nUSER a\n")
                if f.rule_id == "DCK005"]
    assert findings
    assert findings[0].severity in {Severity.HIGH, Severity.CRITICAL}
    # The literal value must be masked in the evidence.
    assert "abcd1234" not in (findings[0].evidence or "")


def test_aws_key_is_critical() -> None:
    findings = [f for f in _findings("FROM alpine:3.19\nRUN echo AKIAIOSFODNN7EXAMPLE\nUSER a\n")
                if f.rule_id == "DCK005"]
    assert findings and findings[0].severity == Severity.CRITICAL


def test_variable_reference_is_not_a_secret() -> None:
    assert "DCK005" not in _rule_ids("FROM alpine:3.19\nARG TOKEN=${BUILD_TOKEN}\nUSER a\n")


def test_risky_port_ssh() -> None:
    assert "DCK006" in _rule_ids("FROM alpine:3.19\nEXPOSE 22\nUSER a\n")


def test_normal_port_is_clean() -> None:
    assert "DCK006" not in _rule_ids("FROM alpine:3.19\nEXPOSE 8080\nUSER a\n")


def test_add_local_non_archive() -> None:
    assert "DCK011" in _rule_ids("FROM alpine:3.19\nADD app.py /app.py\nUSER a\n")


def test_copy_specific_is_clean() -> None:
    assert "DCK010" not in _rule_ids("FROM alpine:3.19\nCOPY app.py /app.py\nUSER a\n")


def test_missing_multistage_build() -> None:
    assert "DCK009" in _rule_ids("FROM golang:1.22\nRUN go build -o app ./...\nUSER 1000\n")


def test_multistage_build_is_clean_for_dck009() -> None:
    text = (
        "FROM golang:1.22 AS build\n"
        "RUN go build -o app ./...\n"
        "FROM alpine:3.19\n"
        "COPY --from=build /app /app\n"
        "USER 1000\n"
    )
    assert "DCK009" not in _rule_ids(text)


def test_suspicious_pipe_to_shell_is_high() -> None:
    findings = [f for f in _findings("FROM alpine:3.19\nRUN wget -qO- x.sh | bash\nUSER a\n")
                if f.rule_id == "DCK014"]
    assert findings and findings[0].severity == Severity.HIGH


def test_findings_carry_full_schema() -> None:
    finding = next(f for f in _findings(VULNERABLE) if f.rule_id == "DCK003")
    assert finding.scanner == "docker-rules"
    assert finding.title
    assert finding.description
    assert finding.recommendation
    assert finding.line_number is not None
    assert finding.confidence is not None
    assert finding.category is not None


def test_pip_cache_env_suppresses_dck008() -> None:
    # `ENV PIP_NO_CACHE_DIR=1` disables the pip cache, so `pip install` without
    # --no-cache-dir must NOT be flagged (regression: DCK008 false positive).
    with_env = (
        "FROM python:3.11-slim\n"
        "ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1\n"
        "RUN pip install --upgrade pip && pip install .\n"
    )
    assert "DCK008" not in _rule_ids(with_env)

    # Without the env (and without --no-cache-dir) it is still flagged.
    without_env = "FROM python:3.11-slim\nRUN pip install .\n"
    assert "DCK008" in _rule_ids(without_env)
