"""The finding value object emitted by scanners.

`RuleFinding` is a pure, immutable description of a single issue. Scanners key
findings by repository-relative file path; the persistence layer resolves the
concrete `file_id` when storing them. Keeping scanners free of database concerns
keeps them deterministic and trivially unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass

from models.enums import Confidence, FindingCategory, Severity


@dataclass(frozen=True, slots=True)
class RuleFinding:
    """A single issue reported by a scanner."""

    rule_id: str
    scanner: str
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    recommendation: str
    file_path: str
    line_number: int | None = None
    evidence: str | None = None
