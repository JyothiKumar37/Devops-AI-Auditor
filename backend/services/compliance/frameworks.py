"""Compliance framework definitions (extensible mapping architecture).

Each control maps to the deterministic cloud rule ids whose findings indicate a
failure, plus the AWS services the control applies to. Only controls that can be
evaluated from the evidence we actually collect are included - we never claim a
control passes merely because nothing was collected (that becomes NOT_ASSESSED).

Adding a framework = adding a list of ControlDef entries. The example framework
is a representative subset of CIS AWS Foundations; NIST/SOC2/PCI can be added the
same way by mapping their controls to the same rule ids.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ControlDef:
    control_id: str
    title: str
    description: str
    rule_ids: tuple[str, ...]
    services: tuple[str, ...]  # AWS services the control applies to
    remediation: str
    frameworks: tuple[str, ...] = field(default_factory=lambda: ("CIS_AWS",))


# Representative CIS AWS Foundations subset (evaluable from collected evidence).
_CIS_AWS: list[ControlDef] = [
    ControlDef(
        "CIS-4.1", "No security group allows ingress from 0.0.0.0/0 to admin ports",
        "Security groups must not expose SSH (22) or RDP (3389) to the internet.",
        ("AWS-SG-001", "AWS-SG-003"), ("ec2",),
        "Restrict admin ports to trusted CIDRs or use SSM Session Manager.",
    ),
    ControlDef(
        "CIS-5.2", "No security group allows ingress from 0.0.0.0/0 to database ports",
        "Databases must not be reachable from the internet via security groups.",
        ("AWS-SG-002", "AWS-SG-003"), ("ec2",),
        "Remove public database ingress; allow only private/app security groups.",
    ),
    ControlDef(
        "CIS-4.2", "EC2 instances enforce IMDSv2",
        "Instance metadata service v2 (token-required) must be enforced.",
        ("AWS-EC2-001",), ("ec2",),
        "Set metadata HttpTokens=required on all instances.",
    ),
    ControlDef(
        "CIS-2.1.1", "S3 buckets have default encryption",
        "All S3 buckets must enable default server-side encryption.",
        ("AWS-S3-002",), ("s3",),
        "Enable default encryption (SSE-S3 or SSE-KMS) on every bucket.",
    ),
    ControlDef(
        "CIS-2.1.5", "S3 buckets block public access",
        "S3 Block Public Access must be fully enabled; no public bucket policies.",
        ("AWS-S3-001",), ("s3",),
        "Enable all four Block Public Access settings and remove public policies.",
    ),
    ControlDef(
        "CIS-2.3.1", "RDS instances encrypt storage at rest",
        "RDS storage encryption must be enabled.",
        ("AWS-RDS-002",), ("rds",),
        "Enable storage encryption (via encrypted snapshot/restore).",
    ),
    ControlDef(
        "CIS-2.3.3", "RDS instances are not publicly accessible",
        "RDS databases must not be internet-reachable.",
        ("AWS-RDS-001",), ("rds",),
        "Set PubliclyAccessible=false and place databases in private subnets.",
    ),
    ControlDef(
        "CIS-2.3.2", "RDS automated backups are enabled",
        "RDS instances must retain automated backups.",
        ("AWS-RDS-003",), ("rds",),
        "Set a backup retention period of at least 7 days.",
    ),
    ControlDef(
        "CIS-1.10", "IAM users have MFA enabled",
        "IAM users must have an MFA device registered.",
        ("AWS-IAM-001",), ("iam",),
        "Register an MFA device for every IAM user with console access.",
    ),
    ControlDef(
        "CIS-1.16", "IAM roles do not trust any principal",
        "IAM role trust policies must not use a wildcard principal.",
        ("AWS-IAM-002",), ("iam",),
        "Scope role trust policies to specific accounts/services.",
    ),
    ControlDef(
        "CIS-5.4.1", "EKS cluster endpoints are not open to the internet",
        "EKS public API endpoints must not allow 0.0.0.0/0.",
        ("AWS-EKS-001",), ("eks",),
        "Restrict public access CIDRs or disable the public endpoint.",
    ),
]

FRAMEWORKS: dict[str, list[ControlDef]] = {
    "CIS_AWS": _CIS_AWS,
}

FRAMEWORK_LABELS = {
    "CIS_AWS": "CIS AWS Foundations",
    "NIST": "NIST 800-53 (mapping)",
    "SOC2": "SOC 2 (mapping)",
    "PCI_DSS": "PCI DSS (mapping)",
}


def get_framework(framework: str) -> list[ControlDef]:
    return FRAMEWORKS.get(framework, [])
