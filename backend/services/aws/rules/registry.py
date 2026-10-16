"""Registry of all cloud security rules."""

from __future__ import annotations

from services.aws.rules import checks
from services.aws.rules.base import CloudRule

_RULES: list[CloudRule] = [
    checks.SgAdminPortOpen(),
    checks.SgDatabasePortOpen(),
    checks.SgAllPortsOpen(),
    checks.Ec2ImdsV2NotEnforced(),
    checks.S3BucketPublic(),
    checks.S3BucketUnencrypted(),
    checks.RdsPubliclyAccessible(),
    checks.RdsUnencrypted(),
    checks.RdsNoBackups(),
    checks.IamUserNoMfa(),
    checks.IamRoleWildcardTrust(),
    checks.EksPublicEndpointOpen(),
]


def all_rules() -> list[CloudRule]:
    return list(_RULES)


def rules_for_service(service: str) -> list[CloudRule]:
    return [r for r in _RULES if r.service == service]
