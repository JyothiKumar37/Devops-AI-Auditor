"""Deterministic GitHub Actions workflow analyzer.

Parses a workflow into its trigger/permission/job/step structure and applies
rule-based checks. It never infers runtime behaviour - findings come only from
what the workflow file actually declares.
"""

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

SCANNER_NAME = "github-actions-rules"

C = FindingCategory
S = Severity
CF = Confidence

RULES: dict[str, RuleSpec] = {
    "GHA000": RuleSpec(C.CONFIGURATION, S.HIGH, CF.HIGH,
        "Invalid workflow YAML", "Fix the workflow so it is valid YAML."),
    "GHA001": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Workflow grants write-all permissions",
        "Set least-privilege permissions (default read-only, elevate per job)."),
    "GHA002": RuleSpec(C.SECURITY, S.INFO, CF.MEDIUM,
        "No explicit GITHUB_TOKEN permissions",
        "Declare top-level 'permissions:' (start from read-only)."),
    "GHA003": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Uses pull_request_target",
        "Avoid pull_request_target with checkout of untrusted PR code."),
    "GHA004": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Script injection from untrusted input",
        "Pass ${{ github.event.* }} via env vars, not inline in run scripts."),
    "GHA005": RuleSpec(C.SUPPLY_CHAIN, S.HIGH, CF.HIGH,
        "Action pinned to a mutable branch",
        "Pin third-party actions to a full commit SHA."),
    "GHA006": RuleSpec(C.SUPPLY_CHAIN, S.MEDIUM, CF.MEDIUM,
        "Third-party action not pinned to a commit SHA",
        "Pin third-party actions to a full commit SHA, not a tag."),
    "GHA007": RuleSpec(C.SUPPLY_CHAIN, S.LOW, CF.LOW,
        "Action pinned to a tag rather than a SHA",
        "Consider pinning to a full commit SHA for supply-chain safety."),
    "GHA008": RuleSpec(C.SECRETS, S.CRITICAL, CF.HIGH,
        "Hardcoded secret in workflow",
        "Use encrypted secrets (${{ secrets.NAME }}), never literals."),
    "GHA009": RuleSpec(C.SECRETS, S.MEDIUM, CF.MEDIUM,
        "Secret written to logs",
        "Do not echo secrets; mask them or avoid printing."),
    "GHA010": RuleSpec(C.SECRETS, S.HIGH, CF.HIGH,
        "docker login with an inline password",
        "Use --password-stdin with a secret, not an inline password."),
    "GHA011": RuleSpec(C.SECURITY, S.HIGH, CF.MEDIUM,
        "Self-hosted runner on an untrusted trigger",
        "Do not run untrusted PR code on self-hosted runners."),
    "GHA012": RuleSpec(C.SECURITY, S.MEDIUM, CF.MEDIUM,
        "Production environment deployed from a pull request",
        "Restrict production deployments to protected branches."),
    "GHA013": RuleSpec(C.CONFIGURATION, S.LOW, CF.MEDIUM,
        "Overly broad artifact upload path",
        "Upload only specific files to avoid leaking secrets or sources."),
    "GHA014": RuleSpec(C.SECURITY, S.MEDIUM, CF.HIGH,
        "Remote script piped into a shell",
        "Download, verify, then execute; avoid curl | sh."),
    "GHA015": RuleSpec(C.RELIABILITY, S.INFO, CF.LOW,
        "No automated tests detected in CI",
        "Add a test step to the CI workflows."),
    "GHA016": RuleSpec(C.SECURITY, S.INFO, CF.LOW,
        "No security scanning detected in CI",
        "Add SAST/dependency/container scanning to CI."),
}

_UNTRUSTED_CONTEXT_RE = re.compile(
    r"\$\{\{\s*(github\.event\.[A-Za-z0-9_.\[\]'\"-]+|github\.head_ref|"
    r"github\.pull_request[A-Za-z0-9_.]*)",
)
_ECHO_SECRET_RE = re.compile(
    r"(echo|printf|print|cat)\b[^\n]*(\$\{\{\s*secrets\.|\$[A-Za-z_]*"
    r"(SECRET|TOKEN|PASSWORD|KEY))",
    re.IGNORECASE,
)
_DOCKER_LOGIN_PW_RE = re.compile(
    r"docker\s+login\b[^\n]*(?:-p|--password[= ])\s*([^\s\"']+)", re.IGNORECASE
)
_MUTABLE_REFS = {"main", "master", "head", "develop", "latest", "trunk"}
_OFFICIAL_OWNERS = {"actions", "github", "docker"}
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_BROAD_ARTIFACT_PATHS = {".", "./", "/", "*", "**", "**/*"}
_PROD_ENV_RE = re.compile(r"prod", re.IGNORECASE)
_TEST_HINT_RE = re.compile(
    r"\b(test|pytest|jest|go test|mvn test|npm test|ctest|tox)\b", re.IGNORECASE
)
_SCAN_HINT_RE = re.compile(
    r"\b(codeql|trivy|snyk|semgrep|bandit|grype|checkov|tfsec|gitleaps?|"
    r"dependency-check|sonar)\b",
    re.IGNORECASE,
)


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _triggers(doc: dict) -> set[str]:
    # PyYAML parses the bare key `on` as the boolean True (YAML 1.1).
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if isinstance(on, dict):
        return {str(k) for k in on}
    return set()


def _jobs(doc: dict) -> dict:
    return _as_dict(doc.get("jobs"))


def analyze_github_workflow(file_path: str, text: str) -> list[RuleFinding]:
    """Analyse a single GitHub Actions workflow file."""
    try:
        documents = load_documents(text)
    except YamlSyntaxError as exc:
        emit = Emitter(RULES, SCANNER_NAME, file_path)
        emit.add("GHA000", description=f"Workflow could not be parsed: {exc.message}",
                 line=exc.line)
        return emit.findings

    if not documents or not isinstance(documents[0], dict):
        return []

    doc = documents[0]
    emit = Emitter(RULES, SCANNER_NAME, file_path)
    triggers = _triggers(doc)
    jobs = _jobs(doc)

    _check_permissions(doc, jobs, emit)
    _check_triggers(doc, triggers, jobs, emit)
    _check_env_secrets(doc.get("env"), line_of(doc, "env"), emit)

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_line = line_of(jobs, job_name)
        _check_env_secrets(job.get("env"), line_of(job, "env") or job_line, emit)
        _check_self_hosted(job, job_name, job_line, triggers, emit)
        for step in _as_list(job.get("steps")):
            if isinstance(step, dict):
                _check_step(step, emit)

    return emit.findings


def _check_permissions(doc: dict, jobs: dict, emit: Emitter) -> None:
    top = doc.get("permissions")
    if top == "write-all":
        emit.add("GHA001", description="Top-level permissions grant write-all.",
                 line=line_of(doc, "permissions"), evidence="permissions: write-all")
    declared = top is not None or any(
        isinstance(job, dict) and "permissions" in job for job in jobs.values()
    )
    for job_name, job in jobs.items():
        if isinstance(job, dict) and job.get("permissions") == "write-all":
            emit.add("GHA001", description=f"Job '{job_name}' grants write-all permissions.",
                     line=line_of(job, "permissions") or line_of(jobs, job_name),
                     evidence="permissions: write-all")
    if not declared:
        emit.add("GHA002", description="No GITHUB_TOKEN permissions are declared.", line=1)


def _check_triggers(doc: dict, triggers: set[str], jobs: dict, emit: Emitter) -> None:
    if "pull_request_target" in triggers:
        emit.add("GHA003", description="Workflow is triggered by pull_request_target.",
                 line=line_of(doc, "on") or line_of(doc, True) or 1,
                 evidence="on: pull_request_target")
    untrusted_trigger = bool(triggers & {"pull_request", "pull_request_target"})
    if untrusted_trigger:
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            env = job.get("environment")
            env_name = env.get("name") if isinstance(env, dict) else env
            if isinstance(env_name, str) and _PROD_ENV_RE.search(env_name):
                emit.add("GHA012",
                         description=f"Job '{job_name}' deploys to environment "
                         f"'{env_name}' on a pull_request trigger.",
                         line=line_of(job, "environment") or line_of(jobs, job_name),
                         evidence=f"environment: {env_name}")


def _check_self_hosted(
    job: dict, job_name: str, job_line: int | None, triggers: set[str], emit: Emitter
) -> None:
    runs_on = job.get("runs-on")
    values = runs_on if isinstance(runs_on, list) else [runs_on]
    is_self_hosted = any(isinstance(v, str) and "self-hosted" in v for v in values)
    if is_self_hosted and (triggers & {"pull_request", "pull_request_target"}):
        emit.add("GHA011",
                 description=f"Job '{job_name}' runs on a self-hosted runner with an "
                 "untrusted PR trigger.",
                 line=line_of(job, "runs-on") or job_line,
                 evidence=f"runs-on: {runs_on}")


def _check_step(step: dict, emit: Emitter) -> None:
    uses = step.get("uses")
    if isinstance(uses, str):
        _check_action_pinning(uses, line_of(step, "uses"), emit)
        _check_artifact_upload(step, uses, emit)

    _check_env_secrets(step.get("with"), line_of(step, "with"), emit)
    _check_env_secrets(step.get("env"), line_of(step, "env"), emit)

    run = step.get("run")
    if isinstance(run, str):
        run_line = line_of(step, "run")
        untrusted = _UNTRUSTED_CONTEXT_RE.search(run)
        if untrusted:
            emit.add("GHA004", description="Untrusted input is interpolated into a run script.",
                     line=run_line, evidence=untrusted.group(0))
        if _ECHO_SECRET_RE.search(run):
            emit.add("GHA009", description="A secret is echoed to the build log.",
                     line=run_line)
        if CURL_PIPE_SH_RE.search(run):
            emit.add("GHA014", description="A remote script is piped into a shell.",
                     line=run_line)
        pw = _DOCKER_LOGIN_PW_RE.search(run)
        if pw and not pw.group(1).startswith("$") and "--password-stdin" not in run:
            emit.add("GHA010", description="docker login uses an inline password.",
                     line=run_line, evidence="docker login -p ****")


def _check_action_pinning(uses: str, line: int | None, emit: Emitter) -> None:
    if uses.startswith("./") or uses.startswith("docker://") or "@" not in uses:
        return
    repo, ref = uses.rsplit("@", 1)
    owner = repo.split("/", 1)[0]
    if _SHA_RE.match(ref):
        return
    if ref.lower() in _MUTABLE_REFS:
        emit.add("GHA005", description=f"Action '{uses}' is pinned to mutable ref '{ref}'.",
                 line=line, evidence=f"uses: {uses}")
    elif owner in _OFFICIAL_OWNERS:
        emit.add("GHA007", description=f"Official action '{uses}' is pinned to a tag.",
                 line=line, evidence=f"uses: {uses}")
    else:
        emit.add("GHA006", description=f"Third-party action '{uses}' is not pinned to a SHA.",
                 line=line, evidence=f"uses: {uses}")


def _check_artifact_upload(step: dict, uses: str, emit: Emitter) -> None:
    if "upload-artifact" not in uses:
        return
    path = _as_dict(step.get("with")).get("path")
    if isinstance(path, str) and path.strip() in _BROAD_ARTIFACT_PATHS:
        emit.add("GHA013", description=f"Artifact upload uses a broad path '{path}'.",
                 line=line_of(step, "with"), evidence=f"path: {path}")


def _check_env_secrets(env: Any, line: int | None, emit: Emitter) -> None:
    if not isinstance(env, dict):
        return
    for key, value in env.items():
        if not isinstance(value, str):
            continue
        if is_reference_value(value):
            continue
        if looks_like_secret_value(value) or SECRET_KEY_RE.search(str(key)):
            emit.add("GHA008", description=f"'{key}' is set to a literal secret value.",
                     line=line_of(env, key) or line, evidence=f"{key}={mask(value)}")


def analyze_github_repo(files: list[tuple[str, str]]) -> list[RuleFinding]:
    """Repo-level GitHub Actions checks across all workflows (missing test/scan)."""
    if not files:
        return []
    has_tests = False
    has_scanning = False
    for _path, text in files:
        if _TEST_HINT_RE.search(text):
            has_tests = True
        if _SCAN_HINT_RE.search(text):
            has_scanning = True

    first_path = files[0][0]
    emit = Emitter(RULES, SCANNER_NAME, first_path)
    if not has_tests:
        emit.add("GHA015", description="No workflow appears to run automated tests.", line=1)
    if not has_scanning:
        emit.add("GHA016", description="No workflow appears to run security scanning.", line=1)
    return emit.findings
