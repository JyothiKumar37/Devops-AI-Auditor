"""Deterministic Terraform rule engine.

Pure, evidence-based checks over the module model. Findings are only raised when
the configuration itself provides the evidence (e.g. an attribute is explicitly
set to an insecure value, or a reference cannot be resolved). "Missing X" is only
flagged when X is genuinely expected - and for context-dependent settings such as
multi-AZ or deletion protection we require a production signal rather than
assuming every resource needs them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from models.enums import Confidence, FindingCategory, Severity
from scanners.finding import RuleFinding
from scanners.terraform.model import (
    TfModule,
    TfResource,
    extract_references,
    used_variable_names,
    walk_strings,
)

SCANNER_NAME = "terraform-rules"

C = FindingCategory
S = Severity
CF = Confidence


@dataclass(frozen=True, slots=True)
class RuleSpec:
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    title: str
    recommendation: str


RULES: dict[str, RuleSpec] = {
    "TF000": RuleSpec(C.CONFIGURATION, S.HIGH, CF.HIGH,
        "Invalid Terraform configuration", "Fix the HCL so it parses."),
    "TF001": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Security group open to 0.0.0.0/0",
        "Restrict ingress CIDRs to known networks."),
    "TF002": RuleSpec(C.SECURITY, S.CRITICAL, CF.HIGH,
        "SSH open to the world (0.0.0.0/0:22)",
        "Restrict SSH to specific IPs or use a bastion/SSM."),
    "TF003": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Database port open to the world",
        "Restrict database ports to application security groups only."),
    "TF004": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Publicly accessible RDS instance",
        "Set publicly_accessible = false and place the DB in private subnets."),
    "TF005": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Publicly accessible S3 bucket",
        "Remove public ACLs and enable a public access block."),
    "TF006": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Unencrypted resource",
        "Enable encryption at rest (storage_encrypted / encrypted = true)."),
    "TF007": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Overly permissive IAM policy",
        "Avoid wildcard Action/Resource/Principal; grant least privilege."),
    "TF008": RuleSpec(C.SECRETS, S.CRITICAL, CF.HIGH,
        "Hardcoded credential or secret",
        "Remove secrets from code; use variables, Secrets Manager or SSM."),
    "TF010": RuleSpec(C.RELIABILITY, S.MEDIUM, CF.HIGH,
        "Database backups disabled",
        "Set backup_retention_period > 0."),
    "TF011": RuleSpec(C.RELIABILITY, S.MEDIUM, CF.MEDIUM,
        "Deletion protection disabled for a production resource",
        "Enable deletion_protection for production resources."),
    "TF012": RuleSpec(C.RELIABILITY, S.LOW, CF.LOW,
        "Multi-AZ not enabled for a production database",
        "Consider multi_az = true for production databases."),
    "TF013": RuleSpec(C.RELIABILITY, S.LOW, CF.MEDIUM,
        "Load balancer without a health check",
        "Configure a health check for the load balancer."),
    "TF014": RuleSpec(C.RELIABILITY, S.INFO, CF.MEDIUM,
        "Versioned bucket without lifecycle rules",
        "Add lifecycle rules to expire old object versions."),
    "TF020": RuleSpec(C.CONFIGURATION, S.LOW, CF.MEDIUM,
        "Resource is missing tags",
        "Add tags for ownership, cost allocation and governance."),
    "TF021": RuleSpec(C.CONFIGURATION, S.MEDIUM, CF.HIGH,
        "Reference to an undefined symbol",
        "Define the referenced variable/local/resource or fix the reference."),
    "TF022": RuleSpec(C.CONFIGURATION, S.LOW, CF.HIGH,
        "Declared variable is never used",
        "Remove the unused variable or reference it."),
    "TF023": RuleSpec(C.CONFIGURATION, S.INFO, CF.MEDIUM,
        "Variable has no type constraint",
        "Add a type to the variable for validation."),
    "TF024": RuleSpec(C.SECRETS, S.MEDIUM, CF.MEDIUM,
        "Sensitive variable not marked sensitive",
        "Mark secret variables with sensitive = true."),
    "TF025": RuleSpec(C.CONFIGURATION, S.MEDIUM, CF.HIGH,
        "depends_on references an undefined resource",
        "Reference an existing resource address."),
}

_DB_PORTS = {3306, 5432, 1433, 1521, 27017, 6379, 5984, 9200, 11211, 9042}
_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
_SECRET_ATTRS = {
    "password", "master_password", "secret_key", "access_key", "private_key",
    "client_secret", "token", "secret",
}
_SECRET_VAR_RE = re.compile(r"(password|secret|passwd|token|api[_-]?key|private[_-]?key)",
                            re.IGNORECASE)
_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")
_TAGGABLE = {
    "aws_instance", "aws_s3_bucket", "aws_db_instance", "aws_rds_cluster", "aws_vpc",
    "aws_subnet", "aws_security_group", "aws_lb", "aws_elb", "aws_alb", "aws_eks_cluster",
    "aws_ebs_volume", "aws_dynamodb_table", "aws_sns_topic", "aws_sqs_queue",
    "aws_kms_key", "aws_cloudwatch_log_group", "aws_iam_role", "aws_ecs_cluster",
    "aws_ecs_service", "aws_efs_file_system", "aws_secretsmanager_secret",
}
_IAM_POLICY_TYPES = {
    "aws_iam_policy", "aws_iam_role_policy", "aws_iam_group_policy",
    "aws_iam_user_policy", "aws_iam_role",
}


class Emitter:
    def __init__(self) -> None:
        self.findings: list[RuleFinding] = []

    def add(
        self,
        rule_id: str,
        file_path: str,
        *,
        description: str,
        line: int | None = None,
        evidence: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
    ) -> None:
        spec = RULES[rule_id]
        self.findings.append(
            RuleFinding(
                rule_id=rule_id,
                scanner=SCANNER_NAME,
                category=spec.category,
                severity=severity or spec.severity,
                confidence=confidence or spec.confidence,
                title=spec.title,
                description=description,
                recommendation=spec.recommendation,
                file_path=file_path,
                line_number=line,
                evidence=evidence,
            )
        )


def make_syntax_finding(file_path: str, message: str, line: int | None) -> RuleFinding:
    spec = RULES["TF000"]
    return RuleFinding(
        rule_id="TF000", scanner=SCANNER_NAME, category=spec.category, severity=spec.severity,
        confidence=spec.confidence, title=spec.title,
        description=f"Terraform file could not be parsed: {message}",
        recommendation=spec.recommendation, file_path=file_path, line_number=line, evidence=None,
    )


# --- value helpers ----------------------------------------------------------


def _truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() in {"true", "1"})


def _literal_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and not value.strip().startswith("${")


def _blocks(body: dict, key: str) -> list[dict]:
    value = body.get(key)
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_production(resource: TfResource) -> bool:
    if "prod" in resource.name.lower():
        return True
    tags = resource.body.get("tags")
    if isinstance(tags, dict):
        for key, value in tags.items():
            if str(key).lower() in {"environment", "env", "stage"} and "prod" in str(value).lower():
                return True
    return False


# --- orchestration ----------------------------------------------------------


def analyze_module(module: TfModule, emit: Emitter) -> None:
    for resource in module.resources:
        _check_resource(resource, emit)
    for scope in module.provider_scopes:
        _scan_secrets(scope.body, scope.file_path, scope.line, emit)
    _check_variables(module, emit)
    _check_references(module, emit)


def _check_resource(resource: TfResource, emit: Emitter) -> None:
    rtype = resource.rtype
    if rtype in {"aws_security_group", "aws_security_group_rule"}:
        _check_security_group(resource, emit)
    if rtype in {"aws_db_instance", "aws_rds_cluster"}:
        _check_rds(resource, emit)
    if rtype.startswith("aws_s3_bucket"):
        _check_s3(resource, emit)
    if rtype in {"aws_ebs_volume", "aws_efs_file_system"}:
        _check_encryption(resource, emit)
    if rtype in _IAM_POLICY_TYPES:
        _check_iam(resource, emit)
    if rtype in {"aws_lb", "aws_alb", "aws_elb"}:
        _check_lb(resource, emit)
    _scan_secrets(resource.body, resource.file_path, resource.line, emit, resource=resource)
    _check_tags(resource, emit)


# --- security ---------------------------------------------------------------


def _ingress_rules(resource: TfResource) -> list[dict]:
    if resource.rtype == "aws_security_group_rule":
        if str(resource.body.get("type", "")) == "ingress":
            return [resource.body]
        return []
    return _blocks(resource.body, "ingress")


def _check_security_group(resource: TfResource, emit: Emitter) -> None:
    for rule in _ingress_rules(resource):
        cidrs = rule.get("cidr_blocks") or rule.get("cidr_ipv6_blocks") or []
        if not isinstance(cidrs, list) or not any(c in _OPEN_CIDRS for c in cidrs):
            continue
        from_port = _to_int(rule.get("from_port"))
        to_port = _to_int(rule.get("to_port"))
        protocol = str(rule.get("protocol", "")).lower()
        line = resource.attr_line("ingress") or resource.line
        evidence = f"cidr=0.0.0.0/0 ports={from_port}-{to_port} protocol={protocol}"

        all_ports = protocol in {"-1", "all"} or (from_port == 0 and to_port in (0, 65535))
        if all_ports or _in_range(22, from_port, to_port):
            emit.add("TF002", resource.file_path,
                     description="SSH (port 22) is reachable from 0.0.0.0/0.",
                     line=line, evidence=evidence)
        elif any(_in_range(p, from_port, to_port) for p in _DB_PORTS):
            emit.add("TF003", resource.file_path,
                     description="A database port is reachable from 0.0.0.0/0.",
                     line=line, evidence=evidence)
        else:
            emit.add("TF001", resource.file_path,
                     description="Ingress allows traffic from 0.0.0.0/0.",
                     line=line, evidence=evidence)


def _in_range(port: int, frm: int | None, to: int | None) -> bool:
    if frm is None or to is None:
        return False
    return frm <= port <= to


def _check_rds(resource: TfResource, emit: Emitter) -> None:
    body = resource.body
    if _truthy(body.get("publicly_accessible")):
        emit.add("TF004", resource.file_path,
                 description=f"{resource.address} is publicly accessible.",
                 line=resource.attr_line("publicly_accessible"),
                 evidence="publicly_accessible = true")
    if not _truthy(body.get("storage_encrypted")):
        emit.add("TF006", resource.file_path,
                 description=f"{resource.address} does not enable storage encryption.",
                 line=resource.line, evidence="storage_encrypted not set to true")
    retention = _to_int(body.get("backup_retention_period"))
    if retention == 0:
        emit.add("TF010", resource.file_path,
                 description=f"{resource.address} disables automated backups.",
                 line=resource.attr_line("backup_retention_period"),
                 evidence="backup_retention_period = 0")
    production = _is_production(resource)
    if production and not _truthy(body.get("deletion_protection")):
        emit.add("TF011", resource.file_path,
                 description=f"Production {resource.address} has no deletion protection.",
                 line=resource.line)
    if production and resource.rtype == "aws_db_instance" and not _truthy(body.get("multi_az")):
        emit.add("TF012", resource.file_path,
                 description=f"Production {resource.address} is not multi-AZ.",
                 line=resource.line)


def _check_s3(resource: TfResource, emit: Emitter) -> None:
    body = resource.body
    acl = str(body.get("acl", ""))
    if acl in {"public-read", "public-read-write"}:
        emit.add("TF005", resource.file_path,
                 description=f"{resource.address} has a public ACL '{acl}'.",
                 line=resource.attr_line("acl"), evidence=f"acl = {acl}")

    if resource.rtype == "aws_s3_bucket_public_access_block":
        flags = ("block_public_acls", "block_public_policy", "ignore_public_acls",
                 "restrict_public_buckets")
        disabled = [f for f in flags if body.get(f) is False or str(body.get(f)).lower() == "false"]
        if disabled:
            emit.add("TF005", resource.file_path,
                     description=f"Public access block disables: {', '.join(disabled)}.",
                     line=resource.line, evidence=str(disabled))

    if resource.rtype == "aws_s3_bucket":
        versioning_on = any(_truthy(v.get("enabled")) for v in _blocks(body, "versioning"))
        if versioning_on and not _blocks(body, "lifecycle_rule"):
            emit.add("TF014", resource.file_path,
                     description=f"{resource.address} is versioned but has no lifecycle rules.",
                     line=resource.line)


def _check_encryption(resource: TfResource, emit: Emitter) -> None:
    if not _truthy(resource.body.get("encrypted")):
        emit.add("TF006", resource.file_path,
                 description=f"{resource.address} is not encrypted.",
                 line=resource.line, evidence="encrypted not set to true")


def _check_iam(resource: TfResource, emit: Emitter) -> None:
    for attr in ("policy", "assume_role_policy", "inline_policy"):
        text = resource.body.get(attr)
        if not isinstance(text, str):
            continue
        # Match both JSON ("Action": "*") and jsonencode/HCL (Action = "*") styles.
        action_wild = re.search(r'"?Action"?\s*[:=]\s*(\[\s*)?"\*"', text)
        principal_wild = re.search(r'"?(AWS|Principal)"?\s*[:=]\s*(\[\s*)?"\*"', text)
        if action_wild:
            emit.add("TF007", resource.file_path,
                     description=f"{resource.address} grants wildcard Action ('*').",
                     line=resource.attr_line(attr), evidence='"Action": "*"')
        elif principal_wild:
            emit.add("TF007", resource.file_path,
                     description=f"{resource.address} allows a wildcard Principal ('*').",
                     line=resource.attr_line(attr), evidence='"Principal": "*"')


def _check_lb(resource: TfResource, emit: Emitter) -> None:
    if resource.rtype == "aws_elb" and not _blocks(resource.body, "health_check"):
        emit.add("TF013", resource.file_path,
                 description=f"{resource.address} has no health_check block.",
                 line=resource.line)


def _scan_secrets(
    body: dict,
    file_path: str,
    line: int | None,
    emit: Emitter,
    resource: TfResource | None = None,
) -> None:
    flagged_secret_attr = False
    for key, value in body.items():
        if str(key).lower() in _SECRET_ATTRS and _literal_str(value):
            attr_line = resource.attr_line(str(key)) if resource else line
            emit.add("TF008", file_path,
                     description=f"Attribute '{key}' is set to a literal secret value.",
                     line=attr_line, evidence=f"{key} = <redacted>")
            flagged_secret_attr = True

    # Only run the generic AKIA scan when a secret attribute did not already
    # capture it, to avoid duplicate findings for the same value.
    if not flagged_secret_attr:
        for text in walk_strings(body):
            if _AWS_ACCESS_KEY_RE.search(text):
                emit.add("TF008", file_path, description="An AWS access key ID is hardcoded.",
                         line=line, evidence="AKIA<redacted>")
                break
    for text in walk_strings(body):
        if _PRIVATE_KEY_RE.search(text):
            emit.add("TF008", file_path, description="A private key is embedded in the config.",
                     line=line, evidence="-----BEGIN PRIVATE KEY----- (redacted)")
            break


def _check_tags(resource: TfResource, emit: Emitter) -> None:
    if resource.rtype in _TAGGABLE and not resource.body.get("tags"):
        emit.add("TF020", resource.file_path,
                 description=f"{resource.address} has no tags.",
                 line=resource.line)


# --- variables & references (module level) ----------------------------------


def _check_variables(module: TfModule, emit: Emitter) -> None:
    used = used_variable_names(module)
    for variable in module.variables:
        if variable.name not in used:
            emit.add("TF022", variable.file_path,
                     description=f"Variable '{variable.name}' is declared but never used.",
                     line=variable.line)
        if "type" not in variable.body:
            emit.add("TF023", variable.file_path,
                     description=f"Variable '{variable.name}' has no type constraint.",
                     line=variable.line)
        if _SECRET_VAR_RE.search(variable.name) and not _truthy(variable.body.get("sensitive")):
            emit.add("TF024", variable.file_path,
                     description=f"Variable '{variable.name}' looks sensitive but is not "
                     "marked sensitive.",
                     line=variable.line)


def _check_references(module: TfModule, emit: Emitter) -> None:
    for scope in module.reference_scopes:
        refs = extract_references(scope.body)
        for name in sorted(refs["var"]):
            if name not in {v.name for v in module.variables}:
                emit.add("TF021", scope.file_path,
                         description=f"{scope.label} references undefined var.{name}.",
                         line=scope.line, evidence=f"var.{name}")
        for name in sorted(refs["local"]):
            if name not in module.local_names:
                emit.add("TF021", scope.file_path,
                         description=f"{scope.label} references undefined local.{name}.",
                         line=scope.line, evidence=f"local.{name}")
        for name in sorted(refs["module"]):
            if name not in module.module_names:
                emit.add("TF021", scope.file_path,
                         description=f"{scope.label} references undefined module.{name}.",
                         line=scope.line, evidence=f"module.{name}")
        for addr in sorted(refs["data"]):
            if addr not in module.data_addresses:
                emit.add("TF021", scope.file_path,
                         description=f"{scope.label} references undefined data.{addr}.",
                         line=scope.line, evidence=f"data.{addr}")
        # Resource references: only validate when the type is declared locally,
        # so cross-module/provider references are not false-flagged.
        for addr in sorted(refs["resource"]):
            rtype = addr.split(".", 1)[0]
            if rtype in module.resource_types and addr not in module.resource_addresses:
                emit.add("TF021", scope.file_path,
                         description=f"{scope.label} references undefined {addr}.",
                         line=scope.line, evidence=addr)

    _check_depends_on_addresses(module, emit)


def _check_depends_on_addresses(module: TfModule, emit: Emitter) -> None:
    known = module.resource_addresses | {f"data.{a}" for a in module.data_addresses} | {
        f"module.{m}" for m in module.module_names
    }
    for resource in module.resources:
        depends = resource.body.get("depends_on")
        if not isinstance(depends, list):
            continue
        for dep in depends:
            address = re.sub(r"[${}]", "", str(dep)).strip()
            # Strip attribute suffixes: keep first two segments (type.name).
            parts = address.split(".")
            base = ".".join(parts[:2]) if parts and parts[0] != "module" else ".".join(parts[:2])
            rtype = base.split(".", 1)[0]
            if rtype in module.resource_types and base not in known:
                emit.add("TF025", resource.file_path,
                         description=f"{resource.address} depends_on undefined {base}.",
                         line=resource.attr_line("depends_on") or resource.line,
                         evidence=base)
