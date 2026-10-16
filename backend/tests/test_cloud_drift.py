"""M5 tests: Terraform <-> AWS drift detection (IN_SYNC/DRIFTED/UNKNOWN/NOT_MANAGED)."""

from __future__ import annotations

from services.aws.drift import (
    DRIFTED,
    IN_SYNC,
    NOT_MANAGED,
    UNKNOWN,
    LiveAsset,
    compute_drift,
    parse_terraform_resources,
)

TF_SG = """
resource "aws_security_group" "app" {
  name = "app-sg"
  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

TF_DB = """
resource "aws_db_instance" "main" {
  identifier = "prod-db"
  publicly_accessible = false
}
"""


def _resources(text: str):
    return parse_terraform_resources([("main.tf", text)])


def test_security_group_in_sync() -> None:
    assets = [LiveAsset(
        service="ec2", resource_type="security-group", resource_id="sg-1", name="app-sg",
        attributes={"ingress": [{"from_port": 443, "to_port": 443, "cidrs": ["0.0.0.0/0"]}]},
    )]
    records = compute_drift(_resources(TF_SG), assets)
    sg = [r for r in records if r.service == "ec2" and r.resource_id == "sg-1"]
    assert sg and sg[0].status == IN_SYNC


def test_security_group_drifted() -> None:
    # Terraform declares only 443, but AWS also has 22 + 3389 open at runtime.
    assets = [LiveAsset(
        service="ec2", resource_type="security-group", resource_id="sg-1", name="app-sg",
        attributes={"ingress": [
            {"from_port": 443, "to_port": 443, "cidrs": ["0.0.0.0/0"]},
            {"from_port": 22, "to_port": 22, "cidrs": ["0.0.0.0/0"]},
            {"from_port": 3389, "to_port": 3389, "cidrs": ["0.0.0.0/0"]},
        ]},
    )]
    records = compute_drift(_resources(TF_SG), assets)
    sg = next(r for r in records if r.resource_id == "sg-1")
    assert sg.status == DRIFTED
    assert sg.expected["ingress_ports"] == [443]
    assert 22 in sg.actual["ingress_ports"] and 3389 in sg.actual["ingress_ports"]
    assert any("22" in d for d in sg.differences)


def test_unknown_when_no_live_match() -> None:
    records = compute_drift(_resources(TF_SG), assets=[])
    assert any(r.status == UNKNOWN and r.terraform_address == "aws_security_group.app"
               for r in records)


def test_not_managed_live_resource() -> None:
    assets = [LiveAsset(
        service="rds", resource_type="db-instance", resource_id="rogue-db", name="rogue-db",
        attributes={"publicly_accessible": True},
    )]
    records = compute_drift([], assets)  # no terraform at all
    assert any(r.status == NOT_MANAGED and r.resource_id == "rogue-db" for r in records)


def test_rds_drift_on_public_flag() -> None:
    assets = [LiveAsset(
        service="rds", resource_type="db-instance", resource_id="prod-db", name="prod-db",
        attributes={"publicly_accessible": True},  # TF says false
    )]
    records = compute_drift(_resources(TF_DB), assets)
    db = next(r for r in records if r.resource_id == "prod-db")
    assert db.status == DRIFTED
    assert db.expected["publicly_accessible"] is False
    assert db.actual["publicly_accessible"] is True


def test_parse_terraform_resources_extracts_types() -> None:
    resources = _resources(TF_SG + TF_DB)
    types = {r.rtype for r in resources}
    assert "aws_security_group" in types and "aws_db_instance" in types
