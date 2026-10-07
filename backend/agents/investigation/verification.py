"""Hallucination safeguards: citation verification + deterministic confidence.

The model may only cite evidence it actually retrieved. Before an investigation
result is returned, :func:`verify_citations` intersects the model's claimed
citations with the references genuinely produced by tool calls (collected in the
engine's ``seen_finding_ids`` / ``seen_files``). Anything the model invented is
dropped.

Confidence is NOT the model's self-reported number - :func:`compute_confidence`
derives it deterministically from how much verified, deterministic evidence
backs the answer.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class CitationCheck:
    verified_finding_ids: list[str]
    verified_files: list[str]
    dropped_finding_ids: list[str]
    dropped_files: list[str]

    @property
    def had_hallucination(self) -> bool:
        return bool(self.dropped_finding_ids or self.dropped_files)

    @property
    def has_verified_evidence(self) -> bool:
        return bool(self.verified_finding_ids or self.verified_files)


def verify_citations(
    cited_finding_ids: list[str],
    cited_files: list[str],
    seen_finding_ids: set[str] | list[str],
    seen_files: set[str] | list[str],
) -> CitationCheck:
    """Keep only citations that correspond to genuinely retrieved evidence."""
    seen_f = set(seen_finding_ids)
    seen_p = set(seen_files)
    verified_f = [fid for fid in dict.fromkeys(cited_finding_ids) if fid in seen_f]
    verified_p = [p for p in dict.fromkeys(cited_files) if p in seen_p]
    dropped_f = [fid for fid in dict.fromkeys(cited_finding_ids) if fid not in seen_f]
    dropped_p = [p for p in dict.fromkeys(cited_files) if p not in seen_p]
    return CitationCheck(verified_f, verified_p, dropped_f, dropped_p)


def compute_confidence(check: CitationCheck, *, tool_calls: int, ai_used: bool) -> str:
    """Deterministic confidence from verified-evidence quality (never LLM self-report).

    HIGH   - multiple verified findings plus corroborating file evidence or
             several independent tool observations.
    MEDIUM - at least one piece of verified deterministic evidence.
    LOW    - inference without verified deterministic backing (or AI unavailable).
    """
    if not ai_used:
        return "low"
    n_findings = len(check.verified_finding_ids)
    n_files = len(check.verified_files)
    if n_findings >= 2 and (n_files >= 1 or tool_calls >= 3):
        return "high"
    if n_findings >= 1 or n_files >= 1:
        return "medium"
    return "low"


INSUFFICIENT_EVIDENCE_MESSAGE = (
    "I could not verify this from the available repository evidence. The "
    "deterministic scan data did not provide enough grounded evidence to answer "
    "confidently. Try narrowing the question to a specific scan, finding, or file."
)


def build_citations(check: CitationCheck) -> list[dict[str, str]]:
    """Structured, clickable evidence references for the UI."""
    citations: list[dict[str, str]] = []
    for fid in check.verified_finding_ids:
        citations.append({"type": "finding", "finding_id": fid})
    for path in check.verified_files:
        citations.append({"type": "file", "path": path})
    return citations
