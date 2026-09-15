"""Shared policy for down-ranking findings that live in low-signal paths.

Template/sample env files hold placeholder credentials by convention, and test
fixtures, examples and docs are not production configuration. Findings located
there are capped to LOW severity/confidence across every scanner so they never
surface as HIGH/MEDIUM production blockers. The false-positive review agent then
sweeps the resulting low-impact, non-production findings out of the score.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import PurePosixPath

from models.enums import Confidence, Severity
from scanners.finding import RuleFinding

# Filename suffixes that mark a file as a template rather than live config.
_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")
# Path segments that mark non-production code (tests, fixtures, examples, docs).
_NON_PROD_SEGMENTS = {
    "test", "tests", "__tests__", "__mocks__", "spec", "specs", "e2e",
    "fixture", "fixtures", "mock", "mocks", "example", "examples",
    "sample", "samples", "docs",
}


def is_low_signal_path(file_path: str) -> bool:
    """True for template/sample env files and test/fixture/docs paths."""
    path = PurePosixPath(file_path)
    name = path.name.lower()
    if name.endswith(_TEMPLATE_SUFFIXES):
        return True
    if any(marker in name for marker in (".example.", ".sample.", ".template.")):
        return True
    return bool({segment.lower() for segment in path.parts} & _NON_PROD_SEGMENTS)


def downrank(finding: RuleFinding) -> RuleFinding:
    """Cap a finding to LOW severity/confidence (for low-signal files)."""
    if finding.severity == Severity.LOW and finding.confidence == Confidence.LOW:
        return finding
    return replace(finding, severity=Severity.LOW, confidence=Confidence.LOW)


def downrank_if_low_signal(finding: RuleFinding) -> RuleFinding:
    """Down-rank the finding when its file lives in a low-signal path."""
    if finding.file_path and is_low_signal_path(finding.file_path):
        return downrank(finding)
    return finding
