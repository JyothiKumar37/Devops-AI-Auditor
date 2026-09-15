"""Tests for the shared low-signal down-ranking policy.

The policy must apply to findings from every scanner (not only the secret
scanner) so template/example manifests and test fixtures never surface as
HIGH/MEDIUM production blockers.
"""

from __future__ import annotations

from models.enums import Confidence, FindingCategory, Severity
from scanners.finding import RuleFinding
from scanners.low_signal import downrank_if_low_signal, is_low_signal_path


def _rf(
    file_path: str,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
) -> RuleFinding:
    return RuleFinding(
        rule_id="K8S060",
        scanner="kubernetes-rules",
        category=FindingCategory.SECRETS,
        severity=severity,
        confidence=confidence,
        title="Secret data stored in a manifest",
        description="Secret 'db' embeds data keys.",
        recommendation="Use a secrets manager.",
        file_path=file_path,
    )


def test_low_signal_path_detection() -> None:
    assert is_low_signal_path("k8s/ecom-secrets.example.yaml")
    assert is_low_signal_path("scripts/e2e/seed.js")
    assert is_low_signal_path("tests/fixtures/deploy.yaml")
    assert is_low_signal_path("backend/.env.template")
    assert not is_low_signal_path("k8s/prod/deploy.yaml")
    assert not is_low_signal_path("backend/.env")


def test_non_secret_scanner_finding_downranked_in_template() -> None:
    # A HIGH Kubernetes finding in a *.example.yaml manifest is capped to LOW.
    ranked = downrank_if_low_signal(_rf("k8s/ecom-secrets.example.yaml"))
    assert ranked.severity == Severity.LOW
    assert ranked.confidence == Confidence.LOW


def test_production_findings_are_untouched() -> None:
    original = _rf("k8s/prod/secret.yaml")
    assert downrank_if_low_signal(original) is original
