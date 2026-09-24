"""Tests for AI-assisted remediation.

Two layers:

1. The deterministic fixer engine (``services.remediation``) - every fixer must
   actually resolve its finding when the patched file is re-scanned, and
   unfixable rules must yield "Manual remediation required" (no invention).
2. The remediation API workflow - propose (no mutation), then approval-gated
   apply against the *stored* copy with re-scan verification.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app
from scanners.ansible import AnsibleScanner
from scanners.compose import DockerComposeScanner
from scanners.config import ConfigScanner
from scanners.docker import DockerScanner
from scanners.finding import RuleFinding
from scanners.helm import HelmScanner
from scanners.kubernetes import KubernetesScanner
from scanners.shell import ShellScanner
from scanners.terraform import TerraformScanner
from services.remediation import MANUAL_REQUIRED, build_diff, changed_lines, propose_fix

# ---------------------------------------------------------------------------
# Fixer engine: each fixer must resolve its finding on re-scan
# ---------------------------------------------------------------------------


def _docker(text: str) -> list[RuleFinding]:
    return DockerScanner().analyze_text(text, "Dockerfile")


def _compose(text: str) -> list[RuleFinding]:
    return DockerComposeScanner().analyze_text(text, "docker-compose.yml")


def _k8s(text: str) -> list[RuleFinding]:
    return KubernetesScanner().analyze_manifests([("deploy.yaml", text)])


def _tf(text: str) -> list[RuleFinding]:
    return TerraformScanner().analyze_files([("main.tf", text)])


def _shell(text: str) -> list[RuleFinding]:
    return ShellScanner().analyze_text(text, "deploy.sh")


def _ansible(text: str) -> list[RuleFinding]:
    return AnsibleScanner().analyze_text(text, "site.yml")


def _config(text: str) -> list[RuleFinding]:
    return ConfigScanner().analyze_text(text, "config/app.yaml")


def _helm_values(text: str) -> list[RuleFinding]:
    return HelmScanner().analyze_text(text, "demo/values.yaml")


def _helm_chart(text: str) -> list[RuleFinding]:
    return HelmScanner().analyze_text(text, "demo/Chart.yaml")


def _find(findings: list[RuleFinding], rule_id: str) -> RuleFinding:
    matches = [f for f in findings if f.rule_id == rule_id]
    assert matches, f"expected {rule_id}; got {sorted({f.rule_id for f in findings})}"
    return matches[0]


def _present_at(findings: list[RuleFinding], rule_id: str, line: int | None) -> bool:
    return any(
        f.rule_id == rule_id and (line is None or f.line_number == line) for f in findings
    )


DOCKER_USER_ROOT = "FROM python:3.11-slim\nRUN echo hi\nUSER root\n"
DOCKER_PIP = "FROM python:3.11-slim\nRUN pip install flask\nUSER 1000\n"
DOCKER_ADD = "FROM python:3.11-slim\nADD app.py /app/app.py\nUSER 1000\n"
DOCKER_APT = (
    "FROM ubuntu:20.04\nRUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n"
    "USER 1000\n"
)

COMPOSE_PRIVILEGED = """\
services:
  web:
    image: nginx:1.25
    privileged: true
    user: "1000"
    restart: always
    healthcheck:
      test: ["CMD", "true"]
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 128M
"""

K8S_PRIVILEGED = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: web
          image: nginx:1.25
          securityContext:
            privileged: true
"""

K8S_APE = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: web
          image: nginx:1.25
          securityContext:
            allowPrivilegeEscalation: true
"""

TF_PUBLIC_RDS = """\
resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = true
}
"""

TF_UNENCRYPTED_RDS = """\
resource "aws_db_instance" "db" {
  publicly_accessible = false
  storage_encrypted   = false
}
"""

TF_UNENCRYPTED_EBS = """\
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
  tags              = { Name = "v" }
}
"""

# --- new scanner fix inputs (crafted so the target rule fires cleanly) ------

SHELL_INSECURE = "#!/bin/bash\nset -euo pipefail\ncurl -k https://example.com\n"
ANSIBLE_VALIDATE_CERTS = "get_url:\n  validate_certs: no\n"
ANSIBLE_STATE_LATEST = "apt:\n  state: latest\n"
CONFIG_DEBUG = "debug: true\n"
CONFIG_TLS_VERIFY_FALSE = "ssl_verify: false\n"
CONFIG_INSECURE_SKIP = "insecure_skip_verify: true\n"
CONFIG_AUTH_OFF = "auth: false\n"
HELM_CHART_V1 = "apiVersion: v1\nname: demo\nversion: 1.0.0\n"
HELM_PRIVILEGED = "securityContext:\n  privileged: true\n"
HELM_HOST_NS = "hostNetwork: true\n"
HELM_RUN_AS_ROOT = "securityContext:\n  runAsNonRoot: false\n"
HELM_RUN_AS_USER0 = "securityContext:\n  runAsUser: 0\n"
HELM_APE = "securityContext:\n  allowPrivilegeEscalation: true\n"

RESOLVE_CASES = [
    ("DCK003", DOCKER_USER_ROOT, _docker),
    ("DCK008", DOCKER_PIP, _docker),
    ("DCK011", DOCKER_ADD, _docker),
    ("DCK015", DOCKER_APT, _docker),
    ("DCMP001", COMPOSE_PRIVILEGED, _compose),
    ("K8S001", K8S_PRIVILEGED, _k8s),
    ("K8S006", K8S_APE, _k8s),
    ("TF004", TF_PUBLIC_RDS, _tf),
    ("TF006", TF_UNENCRYPTED_RDS, _tf),
    ("TF006", TF_UNENCRYPTED_EBS, _tf),
    ("SH007", SHELL_INSECURE, _shell),
    ("ANS002", ANSIBLE_VALIDATE_CERTS, _ansible),
    ("ANS006", ANSIBLE_STATE_LATEST, _ansible),
    ("CFG001", CONFIG_DEBUG, _config),
    ("CFG002", CONFIG_TLS_VERIFY_FALSE, _config),
    ("CFG002", CONFIG_INSECURE_SKIP, _config),
    ("CFG005", CONFIG_AUTH_OFF, _config),
    ("HELM001", HELM_CHART_V1, _helm_chart),
    ("HELM011", HELM_PRIVILEGED, _helm_values),
    ("HELM012", HELM_HOST_NS, _helm_values),
    ("HELM013", HELM_RUN_AS_ROOT, _helm_values),
    ("HELM013", HELM_RUN_AS_USER0, _helm_values),
    ("HELM014", HELM_APE, _helm_values),
]


@pytest.mark.parametrize("rule_id, text, scan", RESOLVE_CASES)
def test_fixer_resolves_finding_on_rescan(rule_id, text, scan) -> None:
    finding = _find(scan(text), rule_id)
    outcome = propose_fix(text, rule_id, finding.line_number, finding.evidence)
    assert outcome is not None, f"expected a fix for {rule_id}"
    assert outcome.new_content != text

    # Re-scanning the patched content must no longer raise the same finding.
    rescanned = scan(outcome.new_content)
    assert not _present_at(rescanned, rule_id, finding.line_number)


def test_missing_docker_user_is_appended() -> None:
    # DCK004: no USER at all -> the fixer appends a non-root USER.
    text = "FROM python:3.11-slim\nRUN echo hi\n"
    finding = _find(_docker(text), "DCK004")
    outcome = propose_fix(text, "DCK004", finding.line_number, finding.evidence)
    assert outcome is not None
    assert "USER 1000" in outcome.new_content
    assert not _present_at(_docker(outcome.new_content), "DCK004", None)


# ---------------------------------------------------------------------------
# No invention: unfixable findings must be manual
# ---------------------------------------------------------------------------


def test_latest_tag_is_manual() -> None:
    text = "FROM ubuntu:latest\nUSER 1000\n"
    finding = _find(_docker(text), "DCK001")
    assert propose_fix(text, "DCK001", finding.line_number, finding.evidence) is None


def test_remote_add_is_not_converted_to_copy() -> None:
    # COPY cannot fetch URLs, so ADD <url> has no safe automatic fix.
    text = "FROM python:3.11-slim\nADD https://example.com/a.sh /a.sh\nUSER 1000\n"
    finding = _find(_docker(text), "DCK011")
    assert propose_fix(text, "DCK011", finding.line_number, finding.evidence) is None


def test_missing_encryption_attribute_is_manual() -> None:
    # storage_encrypted absent entirely: inserting it would be inventing structure.
    text = 'resource "aws_db_instance" "db" {\n  publicly_accessible = false\n}\n'
    finding = _find(_tf(text), "TF006")
    assert propose_fix(text, "TF006", finding.line_number, finding.evidence) is None


def test_unmapped_rule_is_manual() -> None:
    assert propose_fix("anything", "SEC001", 1, None) is None


# ---------------------------------------------------------------------------
# Diff helpers
# ---------------------------------------------------------------------------


def test_diff_and_changed_lines() -> None:
    before = "a\nprivileged: true\nc\n"
    after = "a\nprivileged: false\nc\n"
    removed, added = changed_lines(before, after)
    assert "privileged: true" in removed
    assert "privileged: false" in added
    diff = build_diff("f.yml", before, after)
    assert "-privileged: true" in diff
    assert "+privileged: false" in diff


# ---------------------------------------------------------------------------
# API workflow: propose (no mutation) -> approve -> apply -> verify
# ---------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        workspace_root=str(tmp_path / "ws"),
        llm_provider="none",
    )
    with TestClient(create_app(settings=settings)) as test_client:
        yield test_client


def _zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buffer.getvalue()


def _upload(client: TestClient, files: dict[str, bytes]) -> str:
    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("repo.zip", _zip(files), "application/zip")},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _finding_by_rule(client: TestClient, scan_id: str, rule_id: str) -> dict:
    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()["items"]
    matches = [f for f in findings if f["rule_id"] == rule_id]
    assert matches, f"expected {rule_id} in {sorted({f['rule_id'] for f in findings})}"
    return matches[0]


def test_workflow_propose_then_apply_resolves(client: TestClient) -> None:
    scan_id = _upload(client, {"Dockerfile": DOCKER_USER_ROOT.encode()})
    finding = _finding_by_rule(client, scan_id, "DCK003")
    fid = finding["id"]
    file_id = finding["file_id"]

    # Propose: a diff is produced, and nothing is mutated.
    proposal = client.post(
        f"/api/v1/scans/{scan_id}/findings/{fid}/remediation"
    )
    assert proposal.status_code == 200, proposal.text
    body = proposal.json()
    assert body["status"] == "proposed"
    assert body["diff"] and "USER root" in body["before"]
    assert "USER 1000" in body["after"]

    content_before = client.get(
        f"/api/v1/scans/{scan_id}/files/{file_id}/content"
    ).json()["content"]
    assert "USER root" in content_before  # propose did not change the stored copy

    # Approve + apply: patches the stored copy and verifies resolution.
    applied = client.post(
        f"/api/v1/scans/{scan_id}/findings/{fid}/remediation/apply"
    )
    assert applied.status_code == 200, applied.text
    result = applied.json()
    assert result["applied"] is True
    assert result["resolved"] is True

    # The stored copy now reflects the fix, and the finding is gone.
    content_after = client.get(
        f"/api/v1/scans/{scan_id}/files/{file_id}/content"
    ).json()["content"]
    assert "USER 1000" in content_after
    assert "USER root" not in content_after

    remaining = client.get(f"/api/v1/scans/{scan_id}/findings").json()["items"]
    assert not any(f["id"] == fid for f in remaining)


def test_workflow_config_fix_resolves(client: TestClient) -> None:
    # A new-scanner (config) finding must be fixable end to end: propose a diff,
    # apply it to the stored copy, and verify the re-scan clears it.
    scan_id = _upload(client, {"config/app.yaml": b"debug: true\n"})
    finding = _finding_by_rule(client, scan_id, "CFG001")
    fid = finding["id"]

    proposal = client.post(
        f"/api/v1/scans/{scan_id}/findings/{fid}/remediation"
    ).json()
    assert proposal["status"] == "proposed"
    assert "debug: true" in proposal["before"]
    assert "debug: false" in proposal["after"]

    applied = client.post(
        f"/api/v1/scans/{scan_id}/findings/{fid}/remediation/apply"
    ).json()
    assert applied["applied"] is True
    assert applied["resolved"] is True

    remaining = client.get(f"/api/v1/scans/{scan_id}/findings").json()["items"]
    assert not any(f["id"] == fid for f in remaining)


def test_workflow_manual_required_for_unfixable(client: TestClient) -> None:
    scan_id = _upload(client, {"Dockerfile": b"FROM ubuntu:latest\nUSER 1000\n"})
    finding = _finding_by_rule(client, scan_id, "DCK001")
    fid = finding["id"]

    proposal = client.post(
        f"/api/v1/scans/{scan_id}/findings/{fid}/remediation"
    ).json()
    assert proposal["status"] == "manual_required"
    assert proposal["summary"] == MANUAL_REQUIRED
    assert proposal["diff"] is None

    # Applying an unfixable finding changes nothing and reports not resolved.
    applied = client.post(
        f"/api/v1/scans/{scan_id}/findings/{fid}/remediation/apply"
    ).json()
    assert applied["applied"] is False
    assert applied["resolved"] is False
    assert MANUAL_REQUIRED in applied["message"]

    # The finding is still present (not deleted).
    still = _finding_by_rule(client, scan_id, "DCK001")
    assert still["id"] == fid


def test_remediation_unknown_finding_returns_404(client: TestClient) -> None:
    scan_id = _upload(client, {"Dockerfile": DOCKER_USER_ROOT.encode()})
    missing = "00000000-0000-0000-0000-000000000000"
    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{missing}/remediation"
    )
    assert response.status_code == 404
