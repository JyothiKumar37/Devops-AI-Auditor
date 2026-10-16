"""Cloud rule base types + evaluation helpers."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from models.enums import Confidence, FindingCategory, Severity
from services.aws.resources import DiscoveredResource


@dataclass(slots=True)
class CloudRuleFinding:
    """A deterministic cloud security finding produced by a rule."""

    rule_id: str
    service: str
    resource_id: str
    region: str
    severity: Severity
    confidence: Confidence
    category: FindingCategory
    title: str
    description: str
    recommendation: str
    evidence: str = ""
    compliance: list[str] = field(default_factory=list)


class CloudRule:
    """Base class for a cloud security rule.

    Subclasses set the class attributes and implement :meth:`evaluate`, returning
    zero or more findings for a single asset. ``scanner`` is derived from the
    service (e.g. ``aws-ec2``) so cloud findings slot into the existing
    scanner-based posture/scoring model.
    """

    rule_id: str = ""
    service: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.HIGH
    category: FindingCategory = FindingCategory.SECURITY
    compliance: list[str] = []

    def applies_to(self, asset: DiscoveredResource) -> bool:
        return asset.service == self.service

    def evaluate(self, asset: DiscoveredResource) -> Iterable[CloudRuleFinding]:
        raise NotImplementedError

    # -- helper for subclasses ------------------------------------------------
    def _finding(
        self,
        asset: DiscoveredResource,
        *,
        description: str,
        recommendation: str,
        evidence: str = "",
        severity: Severity | None = None,
    ) -> CloudRuleFinding:
        return CloudRuleFinding(
            rule_id=self.rule_id,
            service=self.service,
            resource_id=asset.resource_id,
            region=asset.region,
            severity=severity or self.severity,
            confidence=self.confidence,
            category=self.category,
            title=self.title,
            description=description,
            recommendation=recommendation,
            evidence=evidence,
            compliance=list(self.compliance),
        )


def scanner_for_service(service: str) -> str:
    """The ``scanner`` string used on persisted cloud findings (<=32 chars)."""
    return f"aws-{service}"[:32]


def evaluate_asset(asset: DiscoveredResource, rules: Iterable[CloudRule]) -> list[CloudRuleFinding]:
    """Run every applicable rule against one asset."""
    findings: list[CloudRuleFinding] = []
    for rule in rules:
        if rule.applies_to(asset):
            findings.extend(rule.evaluate(asset))
    return findings
