"""Tests for the deterministic Helm rule engine."""

from __future__ import annotations

from scanners.helm.scanner import HelmScanner


def _ids(text: str, path: str) -> set[str]:
    return {f.rule_id for f in HelmScanner().analyze_text(text, path)}


def _findings(text: str, path: str):
    return HelmScanner().analyze_text(text, path)


# --- Chart.yaml metadata ----------------------------------------------------

def test_chart_helm2_apiversion_and_missing_version() -> None:
    chart = "apiVersion: v1\nname: demo\ndescription: a chart\n"
    ids = _ids(chart, "demo/Chart.yaml")
    assert "HELM001" in ids  # deprecated Helm 2 apiVersion
    assert "HELM002" in ids  # missing version


def test_valid_chart_has_no_metadata_findings() -> None:
    chart = "apiVersion: v2\nname: demo\nversion: 1.2.3\nappVersion: 4.5.6\n"
    assert _findings(chart, "demo/Chart.yaml") == []


# --- values.yaml / template security ---------------------------------------

VULNERABLE_VALUES = """\
image:
  repository: nginx
  tag: latest
securityContext:
  privileged: true
  runAsNonRoot: false
  allowPrivilegeEscalation: true
  capabilities:
    add:
      - SYS_ADMIN
hostNetwork: true
"""


def test_vulnerable_values_triggers_expected_rules() -> None:
    ids = _ids(VULNERABLE_VALUES, "demo/values.yaml")
    assert ids == {"HELM010", "HELM011", "HELM012", "HELM013", "HELM014", "HELM015"}


CLEAN_VALUES = """\
image:
  repository: nginx
  tag: "1.25.3"
securityContext:
  privileged: false
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
hostNetwork: false
"""


def test_clean_values_has_no_findings() -> None:
    assert _findings(CLEAN_VALUES, "demo/values.yaml") == []


def test_templated_values_are_not_flagged() -> None:
    # The value is unknown at scan time, so it must not be reported.
    text = "securityContext:\n  privileged: {{ .Values.privileged }}\n"
    assert "HELM011" not in _ids(text, "demo/templates/deploy.yaml")


def test_latest_image_forms() -> None:
    assert "HELM010" in _ids("image: nginx:latest\n", "demo/values.yaml")
    assert "HELM010" in _ids("  tag: latest\n", "demo/values.yaml")
    assert "HELM010" not in _ids('  tag: "1.25.3"\n', "demo/values.yaml")


def test_run_as_root_forms() -> None:
    assert "HELM013" in _ids("  runAsUser: 0\n", "demo/templates/deploy.yaml")
    assert "HELM013" in _ids("  runAsNonRoot: false\n", "demo/templates/deploy.yaml")


def test_findings_carry_full_schema() -> None:
    finding = next(
        f for f in _findings(VULNERABLE_VALUES, "demo/values.yaml") if f.rule_id == "HELM011"
    )
    assert finding.scanner == "helm-rules"
    assert finding.title and finding.description and finding.recommendation
    assert finding.line_number is not None
    assert finding.category is not None and finding.confidence is not None
