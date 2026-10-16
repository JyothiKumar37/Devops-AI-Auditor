"""Cloud change detection between two synchronizations (pure, testable).

Compares the prior asset state against freshly discovered resources and emits
added / removed / modified changes. A change is ``risk_significant`` only when it
raises exposure (a resource becomes public, a security group opens an admin/db
port to the world, or RDS becomes publicly accessible) - not for every benign
edit, so monitoring does not generate noise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from services.aws.resources import DiscoveredResource

_WORLD = {"0.0.0.0/0", "::/0"}
_RISKY_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379}


@dataclass(slots=True)
class CloudChangeRecord:
    change_type: str  # added | removed | modified
    service: str
    resource_id: str
    detail: dict[str, Any] = field(default_factory=dict)
    risk_significant: bool = False


def _world_open_ports(attributes: dict) -> set[int]:
    ports: set[int] = set()
    for rule in attributes.get("ingress", []):
        if not any(c in _WORLD for c in rule.get("cidrs", [])):
            continue
        if str(rule.get("protocol")) == "-1":
            ports.update(_RISKY_PORTS)
            continue
        frm, to = rule.get("from_port"), rule.get("to_port")
        if frm is None or to is None:
            continue
        ports.update(p for p in _RISKY_PORTS if frm <= p <= to)
    return ports


def detect_changes(
    prior: dict[tuple[str, str], dict], resources: list[DiscoveredResource]
) -> list[CloudChangeRecord]:
    current = {(r.service, r.resource_id): r for r in resources}
    changes: list[CloudChangeRecord] = []

    # Added / modified.
    for key, res in current.items():
        old = prior.get(key)
        if old is None:
            changes.append(
                CloudChangeRecord(
                    change_type="added", service=res.service, resource_id=res.resource_id,
                    detail={"exposure": res.exposure},
                    risk_significant=res.exposure == "public",
                )
            )
            continue
        diffs, risky = _diff(old, res)
        if diffs:
            changes.append(
                CloudChangeRecord(
                    change_type="modified", service=res.service, resource_id=res.resource_id,
                    detail={"changes": diffs}, risk_significant=risky,
                )
            )

    # Removed.
    for key in prior:
        if key not in current:
            service, resource_id = key
            changes.append(
                CloudChangeRecord(
                    change_type="removed", service=service, resource_id=resource_id,
                    detail={}, risk_significant=False,
                )
            )
    return changes


def _diff(old: dict, res: DiscoveredResource) -> tuple[list[str], bool]:
    diffs: list[str] = []
    risky = False

    old_exposure = old.get("exposure")
    if old_exposure != res.exposure:
        diffs.append(f"exposure {old_exposure} -> {res.exposure}")
        if res.exposure == "public":
            risky = True

    old_attrs = old.get("attributes", {}) or {}
    # New world-open risky ports on a security group.
    new_ports = _world_open_ports(res.attributes) - _world_open_ports(old_attrs)
    if new_ports:
        diffs.append(f"new world-open ports {sorted(new_ports)}")
        risky = True

    # RDS public flip.
    if bool(res.attributes.get("publicly_accessible")) and not bool(
        old_attrs.get("publicly_accessible")
    ):
        diffs.append("publicly_accessible false -> true")
        risky = True

    return diffs, risky
