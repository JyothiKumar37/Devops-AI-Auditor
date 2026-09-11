"""Deterministic GitLab CI (.gitlab-ci.yml) analyzer."""

from __future__ import annotations

import re
from typing import Any

from models.enums import Confidence, FindingCategory, Severity
from scanners.cicd.common import (
    CURL_PIPE_SH_RE,
    SECRET_KEY_RE,
    Emitter,
    RuleSpec,
    is_reference_value,
    looks_like_secret_value,
    mask,
)
from scanners.finding import RuleFinding
from scanners.yaml_lines import YamlSyntaxError, line_of, load_documents

SCANNER_NAME = "gitlab-ci-rules"

C = FindingCategory
S = Severity
CF = Confidence

RULES: dict[str, RuleSpec] = {
    "GLC000": RuleSpec(C.CONFIGURATION, S.HIGH, CF.HIGH,
        "Invalid GitLab CI YAML", "Fix the pipeline so it is valid YAML."),
    "GLC001": RuleSpec(C.SECRETS, S.HIGH, CF.MEDIUM,
        "Hardcoded secret in CI variables",
        "Use masked/protected CI variables or a secrets manager, not literals."),
    "GLC002": RuleSpec(C.SECURITY, S.MEDIUM, CF.HIGH,
        "Docker-in-Docker (privileged runner)",
        "Prefer rootless build tools (kaniko/buildah) over dind."),
    "GLC003": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Insecure Docker daemon configuration",
        "Do not disable Docker TLS or expose the daemon over plain TCP."),
    "GLC004": RuleSpec(C.SECURITY, S.MEDIUM, CF.MEDIUM,
        "Production environment without branch protection",
        "Restrict production deployments to protected branches with manual approval."),
    "GLC005": RuleSpec(C.CONFIGURATION, S.LOW, CF.MEDIUM,
        "Overly broad artifact paths",
        "Publish only the specific build outputs needed."),
    "GLC006": RuleSpec(C.RELIABILITY, S.INFO, CF.LOW,
        "Artifacts without an expiry",
        "Set artifacts.expire_in to avoid unbounded storage."),
    "GLC007": RuleSpec(C.CONFIGURATION, S.LOW, CF.MEDIUM,
        "Deployment job without rules/branch restrictions",
        "Add rules/only (or when: manual) so deploys do not run on every pipeline."),
    "GLC008": RuleSpec(C.SECRETS, S.MEDIUM, CF.MEDIUM,
        "Secret echoed in script",
        "Do not echo secret variables in job scripts."),
    "GLC009": RuleSpec(C.SECURITY, S.MEDIUM, CF.HIGH,
        "Remote script piped into a shell",
        "Download, verify, then execute; avoid curl | sh."),
}

_RESERVED = {
    "stages", "variables", "default", "include", "workflow", "image", "services",
    "before_script", "after_script", "cache", "sast", "pages",
}
_BROAD_PATHS = {".", "./", "/", "*", "**", "**/*"}
_ECHO_SECRET_RE = re.compile(
    r"echo\b[^\n]*\$\{?[A-Za-z_]*(SECRET|TOKEN|PASSWORD|KEY|PASSWD)", re.IGNORECASE
)


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _script_lines(job: dict) -> list[str]:
    lines: list[str] = []
    for key in ("before_script", "script", "after_script"):
        value = job.get(key)
        if isinstance(value, str):
            lines.append(value)
        elif isinstance(value, list):
            lines.extend(str(v) for v in value)
    return lines


def analyze_gitlab_ci(file_path: str, text: str) -> list[RuleFinding]:
    try:
        documents = load_documents(text)
    except YamlSyntaxError as exc:
        emit = Emitter(RULES, SCANNER_NAME, file_path)
        emit.add("GLC000", description=f"Pipeline could not be parsed: {exc.message}",
                 line=exc.line)
        return emit.findings

    if not documents or not isinstance(documents[0], dict):
        return []

    doc = documents[0]
    emit = Emitter(RULES, SCANNER_NAME, file_path)

    _check_variables(doc.get("variables"), line_of(doc, "variables"), emit)

    for name, job in doc.items():
        if name in _RESERVED or not isinstance(job, dict):
            continue
        job_line = line_of(doc, name)
        _check_variables(job.get("variables"), line_of(job, "variables") or job_line, emit)
        _check_dind(job, name, job_line, emit)
        _check_environment(job, name, job_line, emit)
        _check_artifacts(job, job_line, emit)
        _check_scripts(job, name, job_line, emit)

    return emit.findings


def _check_variables(variables: Any, line: int | None, emit: Emitter) -> None:
    if not isinstance(variables, dict):
        return
    for key, value in variables.items():
        text_value = str(value)
        if str(key).upper() in {"DOCKER_TLS_CERTDIR"} and text_value == "":
            emit.add("GLC003", description="Docker TLS is disabled (DOCKER_TLS_CERTDIR='').",
                     line=line_of(variables, key) or line, evidence=f"{key}=''")
        if str(key).upper() == "DOCKER_HOST" and "2375" in text_value:
            emit.add("GLC003", description="Docker daemon is exposed over plaintext TCP (2375).",
                     line=line_of(variables, key) or line, evidence=f"{key}={text_value}")
        if is_reference_value(text_value):
            continue
        if looks_like_secret_value(text_value) or SECRET_KEY_RE.search(str(key)):
            emit.add("GLC001", description=f"CI variable '{key}' holds a literal secret.",
                     line=line_of(variables, key) or line, evidence=f"{key}={mask(text_value)}")


def _check_dind(job: dict, name: str, line: int | None, emit: Emitter) -> None:
    services = job.get("services")
    entries: list[str] = []
    for svc in _as_list(services):
        if isinstance(svc, str):
            entries.append(svc)
        elif isinstance(svc, dict):
            entries.append(str(svc.get("name", "")))
    image = job.get("image")
    if isinstance(image, str):
        entries.append(image)
    if any("dind" in e for e in entries):
        emit.add("GLC002", description=f"Job '{name}' uses Docker-in-Docker.",
                 line=line_of(job, "services") or line, evidence="services: docker:dind")


def _check_environment(job: dict, name: str, line: int | None, emit: Emitter) -> None:
    env = job.get("environment")
    env_name = env.get("name") if isinstance(env, dict) else env
    is_prod = isinstance(env_name, str) and re.search(r"prod", env_name, re.IGNORECASE)
    has_rules = any(k in job for k in ("rules", "only", "except"))

    if is_prod:
        rules_text = str(job.get("rules", "")) + str(job.get("only", ""))
        if "merge_request" in rules_text:
            emit.add("GLC004",
                     description=f"Job '{name}' deploys to production on merge requests.",
                     line=line_of(job, "environment") or line, evidence=f"environment: {env_name}")
        elif not has_rules:
            emit.add("GLC004",
                     description=f"Job '{name}' deploys to production with no branch rules.",
                     line=line_of(job, "environment") or line, evidence=f"environment: {env_name}")

    deploy_like = str(job.get("stage", "")).lower() == "deploy" or "deploy" in name.lower()
    manual = str(job.get("when", "")).lower() == "manual"
    if deploy_like and not has_rules and not manual and not is_prod:
        emit.add("GLC007", description=f"Deployment job '{name}' has no rules/branch restrictions.",
                 line=line)


def _check_artifacts(job: dict, line: int | None, emit: Emitter) -> None:
    artifacts = job.get("artifacts")
    if not isinstance(artifacts, dict):
        return
    paths = artifacts.get("paths")
    if isinstance(paths, list) and any(str(p).strip() in _BROAD_PATHS for p in paths):
        emit.add("GLC005", description="Artifacts use a broad path.",
                 line=line_of(job, "artifacts") or line, evidence=f"paths: {paths}")
    if "expire_in" not in artifacts:
        emit.add("GLC006", description="Artifacts have no expire_in.",
                 line=line_of(job, "artifacts") or line)


def _check_scripts(job: dict, name: str, line: int | None, emit: Emitter) -> None:
    for command in _script_lines(job):
        if _ECHO_SECRET_RE.search(command):
            emit.add("GLC008", description=f"Job '{name}' echoes a secret variable.",
                     line=line_of(job, "script") or line)
        if CURL_PIPE_SH_RE.search(command):
            emit.add("GLC009", description=f"Job '{name}' pipes a remote script into a shell.",
                     line=line_of(job, "script") or line)
