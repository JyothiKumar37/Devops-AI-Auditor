"""Stable finding fingerprints.

A fingerprint identifies "the same finding" across different scans of a
repository, independent of scan id, finding id or line number. It is used for
baselining/suppression (and mirrors the matching key used by scan diffing):
`rule_id | file path | evidence`.
"""

from __future__ import annotations


def finding_fingerprint(rule_id: str, path: str | None, evidence: str | None) -> str:
    """Return the canonical fingerprint string for a finding."""
    return "|".join([rule_id, (path or "").strip(), (evidence or "").strip()])
