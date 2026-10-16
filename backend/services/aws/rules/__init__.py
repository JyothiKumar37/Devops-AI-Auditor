"""Deterministic cloud security rules (Phase 4).

Each rule inspects a discovered asset's metadata and may emit a
:class:`CloudRuleFinding`. Rules are context-aware to avoid false positives (for
example an internet-facing load balancer is expected, but an internet-facing
database is a critical concern). Rules carry stable ids (``AWS-<SERVICE>-NNN``)
and compliance control mappings.
"""

from __future__ import annotations

from services.aws.rules.base import CloudRule, CloudRuleFinding, evaluate_asset
from services.aws.rules.registry import all_rules, rules_for_service

__all__ = [
    "CloudRule",
    "CloudRuleFinding",
    "all_rules",
    "evaluate_asset",
    "rules_for_service",
]
