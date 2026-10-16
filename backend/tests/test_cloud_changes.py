"""M9 tests: cloud change detection + risk-significance (monitoring)."""

from __future__ import annotations

from services.aws.changes import detect_changes
from services.aws.resources import DiscoveredResource


def _res(service, rid, exposure="unknown", **attrs) -> DiscoveredResource:
    return DiscoveredResource(
        service=service, resource_type="x", resource_id=rid, exposure=exposure,
        attributes=attrs,
    )


def test_added_public_resource_is_risky() -> None:
    prior = {("ec2", "i-old"): {"exposure": "private", "attributes": {}}}
    changes = detect_changes(prior, [
        _res("ec2", "i-old", "private"),
        _res("rds", "db-new", "public", publicly_accessible=True),
    ])
    added = [c for c in changes if c.change_type == "added"]
    assert added and added[0].resource_id == "db-new" and added[0].risk_significant


def test_removed_resource_not_risky() -> None:
    prior = {("ec2", "i-1"): {"exposure": "private", "attributes": {}}}
    changes = detect_changes(prior, [])
    removed = [c for c in changes if c.change_type == "removed"]
    assert removed and removed[0].resource_id == "i-1" and not removed[0].risk_significant


def test_security_group_newly_opens_ssh_is_risky() -> None:
    prior = {("ec2", "sg-1"): {"exposure": "unknown", "attributes": {"ingress": []}}}
    now = [_res("ec2", "sg-1", "unknown",
                ingress=[{"from_port": 22, "to_port": 22, "cidrs": ["0.0.0.0/0"]}])]
    changes = detect_changes(prior, now)
    mod = [c for c in changes if c.change_type == "modified"]
    assert mod and mod[0].risk_significant
    assert any("world-open" in d for d in mod[0].detail["changes"])


def test_benign_change_not_risky() -> None:
    # Exposure stays private; only a tag-ish attribute changes -> modified but not risky.
    prior = {("ec2", "i-1"): {"exposure": "private", "attributes": {"image_id": "ami-1"}}}
    now = [_res("ec2", "i-1", "private", image_id="ami-2")]
    changes = detect_changes(prior, now)
    # image_id isn't tracked as a diff dimension -> no modified change at all.
    assert not any(c.risk_significant for c in changes)


def test_exposure_private_to_public_is_risky() -> None:
    prior = {("ec2", "i-1"): {"exposure": "private", "attributes": {}}}
    now = [_res("ec2", "i-1", "public", public_ip="1.2.3.4")]
    changes = detect_changes(prior, now)
    mod = next(c for c in changes if c.change_type == "modified")
    assert mod.risk_significant
    assert any("exposure" in d for d in mod.detail["changes"])


def test_rds_public_flip_is_risky() -> None:
    prior = {("rds", "db-1"): {"exposure": "private",
                               "attributes": {"publicly_accessible": False}}}
    now = [_res("rds", "db-1", "public", publicly_accessible=True)]
    changes = detect_changes(prior, now)
    mod = next(c for c in changes if c.change_type == "modified")
    assert mod.risk_significant
