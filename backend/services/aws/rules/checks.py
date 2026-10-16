"""Concrete deterministic cloud security rules.

Context matters: an internet-facing load balancer is expected and NOT flagged,
while an internet-facing database is critical. Rules only fire on evidence
actually present in the discovered metadata.
"""

from __future__ import annotations

from collections.abc import Iterable

from models.enums import Confidence, FindingCategory, Severity
from services.aws.resources import DiscoveredResource
from services.aws.rules.base import CloudRule, CloudRuleFinding

_WORLD = {"0.0.0.0/0", "::/0"}
_ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
_DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB", 6379: "Redis"}


def _world_open(rule: dict) -> bool:
    return any(c in _WORLD for c in rule.get("cidrs", []))


def _covers_port(rule: dict, port: int) -> bool:
    proto = str(rule.get("protocol"))
    if proto == "-1":
        return True
    frm, to = rule.get("from_port"), rule.get("to_port")
    if frm is None or to is None:
        return False
    return int(frm) <= port <= int(to)


def _is_all_ports(rule: dict) -> bool:
    if str(rule.get("protocol")) == "-1":
        return True
    frm, to = rule.get("from_port"), rule.get("to_port")
    return frm == 0 and to == 65535


# ---- Security groups --------------------------------------------------------


class SgAdminPortOpen(CloudRule):
    rule_id = "AWS-SG-001"
    service = "ec2"
    title = "Security group exposes an admin port to the internet"
    severity = Severity.HIGH
    category = FindingCategory.SECURITY
    compliance = ["CIS-5.2"]

    def applies_to(self, asset: DiscoveredResource) -> bool:
        return asset.service == "ec2" and asset.resource_type == "security-group"

    def evaluate(self, asset: DiscoveredResource) -> Iterable[CloudRuleFinding]:
        for rule in asset.attributes.get("ingress", []):
            if not _world_open(rule):
                continue
            for port, label in _ADMIN_PORTS.items():
                if _covers_port(rule, port):
                    yield self._finding(
                        asset,
                        description=(
                            f"Security group {asset.resource_id} allows {label} "
                            f"(port {port}) from 0.0.0.0/0, exposing remote "
                            "administration to the entire internet."
                        ),
                        recommendation=(
                            f"Restrict {label} to a trusted CIDR/VPN or use SSM "
                            "Session Manager instead of a public port."
                        ),
                        evidence=f"ingress {label}/{port} from {rule.get('cidrs')}",
                    )


class SgDatabasePortOpen(CloudRule):
    rule_id = "AWS-SG-002"
    service = "ec2"
    title = "Security group exposes a database port to the internet"
    severity = Severity.CRITICAL
    category = FindingCategory.SECURITY
    compliance = ["CIS-5.2"]

    def applies_to(self, asset: DiscoveredResource) -> bool:
        return asset.service == "ec2" and asset.resource_type == "security-group"

    def evaluate(self, asset: DiscoveredResource) -> Iterable[CloudRuleFinding]:
        for rule in asset.attributes.get("ingress", []):
            if not _world_open(rule):
                continue
            for port, label in _DB_PORTS.items():
                if _covers_port(rule, port):
                    yield self._finding(
                        asset,
                        description=(
                            f"Security group {asset.resource_id} allows {label} "
                            f"(port {port}) from 0.0.0.0/0 - databases must never "
                            "be internet-reachable."
                        ),
                        recommendation=(
                            f"Remove the public {label} ingress; allow only private "
                            "subnets / application security groups."
                        ),
                        evidence=f"ingress {label}/{port} from {rule.get('cidrs')}",
                    )


class SgAllPortsOpen(CloudRule):
    rule_id = "AWS-SG-003"
    service = "ec2"
    title = "Security group allows all ports from the internet"
    severity = Severity.CRITICAL
    category = FindingCategory.SECURITY
    compliance = ["CIS-5.2"]

    def applies_to(self, asset: DiscoveredResource) -> bool:
        return asset.service == "ec2" and asset.resource_type == "security-group"

    def evaluate(self, asset: DiscoveredResource) -> Iterable[CloudRuleFinding]:
        for rule in asset.attributes.get("ingress", []):
            if _world_open(rule) and _is_all_ports(rule):
                yield self._finding(
                    asset,
                    description=(
                        f"Security group {asset.resource_id} allows ALL ports from "
                        "0.0.0.0/0, removing network segmentation entirely."
                    ),
                    recommendation="Replace the open rule with least-privilege ingress.",
                    evidence=f"ingress all-ports from {rule.get('cidrs')}",
                )
                return


# ---- EC2 --------------------------------------------------------------------


class Ec2ImdsV2NotEnforced(CloudRule):
    rule_id = "AWS-EC2-001"
    service = "ec2"
    title = "EC2 instance does not enforce IMDSv2"
    severity = Severity.MEDIUM
    category = FindingCategory.SECURITY
    compliance = ["CIS-4.1"]

    def applies_to(self, asset: DiscoveredResource) -> bool:
        return asset.service == "ec2" and asset.resource_type == "instance"

    def evaluate(self, asset: DiscoveredResource) -> Iterable[CloudRuleFinding]:
        meta = asset.attributes.get("metadata_options") or {}
        if meta and meta.get("HttpTokens") != "required":
            yield self._finding(
                asset,
                description=(
                    f"Instance {asset.resource_id} allows IMDSv1 (HttpTokens="
                    f"{meta.get('HttpTokens')}), which is vulnerable to SSRF "
                    "credential theft."
                ),
                recommendation="Set metadata options HttpTokens=required (IMDSv2).",
                evidence=f"metadata HttpTokens={meta.get('HttpTokens')}",
            )


# ---- S3 ---------------------------------------------------------------------


class S3BucketPublic(CloudRule):
    rule_id = "AWS-S3-001"
    service = "s3"
    title = "S3 bucket is publicly accessible"
    severity = Severity.HIGH
    category = FindingCategory.SECURITY
    compliance = ["CIS-2.1.5"]

    def evaluate(self, asset: DiscoveredResource) -> Iterable[CloudRuleFinding]:
        if asset.attributes.get("policy_status_public"):
            yield self._finding(
                asset,
                description=f"Bucket {asset.resource_id} has a policy that grants public access.",
                recommendation="Remove public statements and enable S3 Block Public Access.",
                evidence="bucket policy status: public",
                severity=Severity.CRITICAL,
            )
            return
        pab = asset.attributes.get("public_access_block") or {}
        fully_blocked = all(
            pab.get(k) for k in (
                "BlockPublicAcls", "IgnorePublicAcls",
                "BlockPublicPolicy", "RestrictPublicBuckets",
            )
        )
        if not fully_blocked:
            yield self._finding(
                asset,
                description=(
                    f"Bucket {asset.resource_id} does not have all Block Public "
                    "Access settings enabled, so it could be exposed publicly."
                ),
                recommendation="Enable all four S3 Block Public Access settings.",
                evidence=f"public_access_block={pab or 'none'}",
            )


class S3BucketUnencrypted(CloudRule):
    rule_id = "AWS-S3-002"
    service = "s3"
    title = "S3 bucket has no default encryption"
    severity = Severity.MEDIUM
    category = FindingCategory.SECURITY
    compliance = ["CIS-2.1.1"]

    def evaluate(self, asset: DiscoveredResource) -> Iterable[CloudRuleFinding]:
        if asset.attributes.get("encryption") is False:
            yield self._finding(
                asset,
                description=f"Bucket {asset.resource_id} has no default server-side encryption.",
                recommendation="Enable default encryption (SSE-S3 or SSE-KMS).",
                evidence="encryption: disabled",
            )


# ---- RDS --------------------------------------------------------------------


class RdsPubliclyAccessible(CloudRule):
    rule_id = "AWS-RDS-001"
    service = "rds"
    title = "RDS instance is publicly accessible"
    severity = Severity.CRITICAL
    category = FindingCategory.SECURITY
    compliance = ["CIS-2.3.3"]

    def evaluate(self, asset: DiscoveredResource) -> Iterable[CloudRuleFinding]:
        if asset.attributes.get("publicly_accessible"):
            yield self._finding(
                asset,
                description=(
                    f"RDS instance {asset.resource_id} is publicly accessible - a "
                    "database should never be reachable from the internet."
                ),
                recommendation="Set PubliclyAccessible=false and place it in private subnets.",
                evidence="publicly_accessible=true",
            )


class RdsUnencrypted(CloudRule):
    rule_id = "AWS-RDS-002"
    service = "rds"
    title = "RDS storage is not encrypted"
    severity = Severity.HIGH
    category = FindingCategory.SECURITY
    compliance = ["CIS-2.3.1"]

    def evaluate(self, asset: DiscoveredResource) -> Iterable[CloudRuleFinding]:
        if asset.attributes.get("storage_encrypted") is False:
            yield self._finding(
                asset,
                description=f"RDS instance {asset.resource_id} does not have storage encryption.",
                recommendation="Enable storage encryption (requires a snapshot/restore).",
                evidence="storage_encrypted=false",
            )


class RdsNoBackups(CloudRule):
    rule_id = "AWS-RDS-003"
    service = "rds"
    title = "RDS automated backups are disabled"
    severity = Severity.MEDIUM
    category = FindingCategory.RELIABILITY
    compliance = ["CIS-2.3.2"]

    def evaluate(self, asset: DiscoveredResource) -> Iterable[CloudRuleFinding]:
        retention = asset.attributes.get("backup_retention_days")
        if retention == 0:
            yield self._finding(
                asset,
                description=f"RDS instance {asset.resource_id} has automated backups disabled.",
                recommendation="Set a backup retention period of at least 7 days.",
                evidence="backup_retention_days=0",
            )


# ---- IAM --------------------------------------------------------------------


class IamUserNoMfa(CloudRule):
    rule_id = "AWS-IAM-001"
    service = "iam"
    title = "IAM user has no MFA device"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = FindingCategory.SECURITY
    compliance = ["CIS-1.10"]

    def applies_to(self, asset: DiscoveredResource) -> bool:
        return asset.service == "iam" and asset.resource_type == "user"

    def evaluate(self, asset: DiscoveredResource) -> Iterable[CloudRuleFinding]:
        if asset.attributes.get("mfa_devices", 0) == 0:
            yield self._finding(
                asset,
                description=f"IAM user {asset.resource_id} has no MFA device registered.",
                recommendation="Enable an MFA device for every IAM user with a console password.",
                evidence="mfa_devices=0",
            )


class IamRoleWildcardTrust(CloudRule):
    rule_id = "AWS-IAM-002"
    service = "iam"
    title = "IAM role trusts any principal (wildcard)"
    severity = Severity.HIGH
    category = FindingCategory.SECURITY
    compliance = ["CIS-1.16"]

    def applies_to(self, asset: DiscoveredResource) -> bool:
        return asset.service == "iam" and asset.resource_type == "role"

    def evaluate(self, asset: DiscoveredResource) -> Iterable[CloudRuleFinding]:
        policy = asset.attributes.get("assume_role_policy") or {}
        for stmt in _statements(policy):
            principal = stmt.get("Principal")
            if principal == "*" or (isinstance(principal, dict) and "*" in principal.values()):
                yield self._finding(
                    asset,
                    description=(
                        f"IAM role {asset.resource_id} has a trust policy that allows "
                        "any principal (\"*\") to assume it."
                    ),
                    recommendation="Scope the trust policy to specific accounts/services.",
                    evidence="assume_role_policy Principal=*",
                )
                return


def _statements(policy: dict) -> list[dict]:
    stmt = policy.get("Statement") if isinstance(policy, dict) else None
    if isinstance(stmt, dict):
        return [stmt]
    return [s for s in stmt if isinstance(s, dict)] if isinstance(stmt, list) else []


# ---- EKS --------------------------------------------------------------------


class EksPublicEndpointOpen(CloudRule):
    rule_id = "AWS-EKS-001"
    service = "eks"
    title = "EKS API endpoint is public to the internet"
    severity = Severity.HIGH
    category = FindingCategory.SECURITY
    compliance = ["CIS-EKS-5.4.1"]

    def evaluate(self, asset: DiscoveredResource) -> Iterable[CloudRuleFinding]:
        attrs = asset.attributes
        if attrs.get("endpoint_public_access") and "0.0.0.0/0" in (
            attrs.get("public_access_cidrs") or []
        ):
            yield self._finding(
                asset,
                description=(
                    f"EKS cluster {asset.resource_id} exposes its public API endpoint "
                    "to 0.0.0.0/0."
                ),
                recommendation=(
                    "Restrict public access CIDRs or disable the public endpoint and "
                    "use private access."
                ),
                evidence="endpoint_public_access=true cidr=0.0.0.0/0",
            )
