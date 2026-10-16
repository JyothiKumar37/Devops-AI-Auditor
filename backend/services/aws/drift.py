"""Terraform (expected) vs AWS (actual) drift detection (pure, testable).

Correlates Terraform-declared resources against discovered live assets and
classifies each into one of four statuses:

- ``IN_SYNC``     - declared in Terraform and the live config matches.
- ``DRIFTED``     - declared in Terraform but the live config differs.
- ``NOT_MANAGED`` - a live resource of a Terraform-managed type with no matching
                    Terraform declaration.
- ``UNKNOWN``     - declared in Terraform but no matching live resource found
                    (not applied yet, in another account, or unmatchable).

This module never mutates Terraform or AWS - it only reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scanners.terraform.model import TfResource

IN_SYNC = "IN_SYNC"
DRIFTED = "DRIFTED"
NOT_MANAGED = "NOT_MANAGED"
UNKNOWN = "UNKNOWN"

# Terraform resource type -> (cloud service, cloud resource_type) it maps to.
_TF_TO_AWS = {
    "aws_security_group": ("ec2", "security-group"),
    "aws_instance": ("ec2", "instance"),
    "aws_s3_bucket": ("s3", "bucket"),
    "aws_db_instance": ("rds", "db-instance"),
    "aws_eks_cluster": ("eks", "cluster"),
}


@dataclass(slots=True)
class LiveAsset:
    """Minimal live-asset view used by drift (decoupled from the ORM for testing)."""

    service: str
    resource_type: str
    resource_id: str
    name: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DriftRecord:
    terraform_address: str | None
    service: str
    resource_id: str
    status: str
    expected: dict[str, Any] = field(default_factory=dict)
    actual: dict[str, Any] = field(default_factory=dict)
    differences: list[str] = field(default_factory=list)


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _tf_ingress_ports(body: dict) -> set[int]:
    ports: set[int] = set()
    ingress = body.get("ingress")
    if isinstance(ingress, list):
        blocks = ingress
    elif isinstance(ingress, dict):
        blocks = [ingress]
    else:
        blocks = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        frm, to = _as_int(block.get("from_port")), _as_int(block.get("to_port"))
        if frm is None or to is None:
            continue
        # Bound the expansion so a 0-65535 block does not explode.
        if to - frm > 1024:
            ports.add(frm)
            ports.add(to)
        else:
            ports.update(range(frm, to + 1))
    return ports


def _live_ingress_ports(attributes: dict) -> set[int]:
    ports: set[int] = set()
    for rule in attributes.get("ingress", []):
        frm, to = _as_int(rule.get("from_port")), _as_int(rule.get("to_port"))
        if frm is None or to is None:
            continue
        if to - frm > 1024:
            ports.add(frm)
            ports.add(to)
        else:
            ports.update(range(frm, to + 1))
    return ports


def _tf_identity(tf: TfResource) -> str:
    body = tf.body
    for key in ("name", "bucket", "identifier"):
        value = body.get(key)
        if isinstance(value, str) and value and "${" not in value:
            return value
    tags = body.get("tags")
    if isinstance(tags, dict) and isinstance(tags.get("Name"), str):
        return tags["Name"]
    return tf.name


def _match_live(
    tf: TfResource, service: str, resource_type: str, assets: list[LiveAsset]
) -> LiveAsset | None:
    identity = _tf_identity(tf)
    candidates = [
        a for a in assets if a.service == service and a.resource_type == resource_type
    ]
    for a in candidates:
        if identity in {a.resource_id, a.name, a.tags.get("Name", "")}:
            return a
    return None


def _compare_security_group(tf: TfResource, asset: LiveAsset) -> tuple[dict, dict, list[str]]:
    expected_ports = sorted(_tf_ingress_ports(tf.body))
    actual_ports = sorted(_live_ingress_ports(asset.attributes))
    unexpected = sorted(set(actual_ports) - set(expected_ports))
    differences = (
        [f"unexpected runtime ingress port {p}" for p in unexpected] if unexpected else []
    )
    return (
        {"ingress_ports": expected_ports},
        {"ingress_ports": actual_ports},
        differences,
    )


def _compare_rds(tf: TfResource, asset: LiveAsset) -> tuple[dict, dict, list[str]]:
    expected_public = bool(tf.body.get("publicly_accessible"))
    actual_public = bool(asset.attributes.get("publicly_accessible"))
    differences = []
    if expected_public != actual_public:
        differences.append(
            f"publicly_accessible: expected {expected_public}, actual {actual_public}"
        )
    return (
        {"publicly_accessible": expected_public},
        {"publicly_accessible": actual_public},
        differences,
    )


def compute_drift(resources: list[TfResource], assets: list[LiveAsset]) -> list[DriftRecord]:
    """Correlate Terraform resources with live assets and classify drift."""
    records: list[DriftRecord] = []
    matched_live: set[tuple[str, str]] = set()

    for tf in resources:
        mapping = _TF_TO_AWS.get(tf.rtype)
        if mapping is None:
            continue
        service, resource_type = mapping
        asset = _match_live(tf, service, resource_type, assets)
        if asset is None:
            records.append(
                DriftRecord(
                    terraform_address=tf.address, service=service, resource_id="",
                    status=UNKNOWN, expected={"declared": True}, actual={},
                    differences=["no matching live resource found"],
                )
            )
            continue
        matched_live.add((asset.service, asset.resource_id))
        if resource_type == "security-group":
            expected, actual, diffs = _compare_security_group(tf, asset)
        elif resource_type == "db-instance":
            expected, actual, diffs = _compare_rds(tf, asset)
        else:
            expected, actual, diffs = {"declared": True}, {"exists": True}, []
        records.append(
            DriftRecord(
                terraform_address=tf.address, service=service,
                resource_id=asset.resource_id,
                status=DRIFTED if diffs else IN_SYNC,
                expected=expected, actual=actual, differences=diffs,
            )
        )

    # Live resources of a Terraform-managed type with no Terraform declaration.
    managed_types = set(_TF_TO_AWS.values())
    for asset in assets:
        if (asset.service, asset.resource_type) in managed_types and (
            asset.service, asset.resource_id
        ) not in matched_live:
            records.append(
                DriftRecord(
                    terraform_address=None, service=asset.service,
                    resource_id=asset.resource_id, status=NOT_MANAGED,
                    expected={}, actual={"exists": True},
                    differences=["live resource is not declared in Terraform"],
                )
            )
    return records


def parse_terraform_resources(files: list[tuple[str, str]]) -> list[TfResource]:
    """Parse (path, text) Terraform files into TfResource objects (best-effort)."""
    import os

    from scanners.terraform.model import TfFile, build_module
    from scanners.terraform.parser import LineIndex, parse_hcl

    by_dir: dict[str, list[TfFile]] = {}
    for path, text in files:
        try:
            parsed = parse_hcl(text)
        except Exception:  # noqa: BLE001 - skip unparseable files
            continue
        by_dir.setdefault(os.path.dirname(path), []).append(TfFile(path, parsed, LineIndex(text)))

    resources: list[TfResource] = []
    for directory, tf_files in by_dir.items():
        module = build_module(directory, tf_files)
        resources.extend(module.resources)
    return resources
