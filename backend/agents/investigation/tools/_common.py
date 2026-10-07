"""Shared helpers for investigation tools (loading + safe serialization)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.investigation.redaction import redact_secrets
from agents.investigation.tools.base import ToolError
from agents.reasoning.sanitize import neutralize
from models.enums import Severity
from models.finding import Finding
from models.scan import RepositoryFile, Scan


async def load_scan(session: AsyncSession, scan_id: uuid.UUID) -> Scan:
    """Load a scan or raise a not_found ToolError."""
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise ToolError(f"Scan {scan_id} not found.", code="not_found")
    return scan


async def load_findings_with_paths(
    session: AsyncSession, scan_id: uuid.UUID
) -> list[tuple[Finding, str | None]]:
    """All findings for a scan with their file path, severity-sorted (desc)."""
    rows = (
        await session.execute(
            select(Finding, RepositoryFile.path)
            .outerjoin(RepositoryFile, Finding.file_id == RepositoryFile.id)
            .where(Finding.scan_id == scan_id)
        )
    ).all()
    items = [(row[0], row[1]) for row in rows]
    items.sort(key=lambda it: -Severity(it[0].severity).rank)
    return items


def finding_to_dict(
    finding: Finding, path: str | None, *, include_evidence: bool = True
) -> dict[str, Any]:
    """Project a finding into a safe, structured, secret-redacted dict for the LLM.

    Free-text fields are neutralized (prompt-injection defense) and evidence is
    secret-redacted. ``is_ai_review`` flags AI-origin findings so the agent never
    treats a probabilistic AI-review finding as a deterministic fact.
    """
    out: dict[str, Any] = {
        "finding_id": str(finding.id),
        "rule_id": finding.rule_id,
        "scanner": finding.scanner,
        "severity": _value(finding.severity),
        "category": _value(finding.category),
        "confidence": _value(finding.confidence),
        "title": neutralize(finding.title, max_length=300),
        "file": neutralize(path, max_length=300) if path else None,
        "line": finding.line_number,
        "is_ai_review": finding.scanner == "ai-review",
    }
    if include_evidence:
        out["description"] = neutralize(finding.description, max_length=600)
        out["evidence"] = neutralize(redact_secrets(finding.evidence), max_length=600) or None
        out["recommendation"] = neutralize(finding.recommendation, max_length=400)
    return out


def _value(enum_or_str: Any) -> str:
    """Return the plain string value of an enum or string (py3.11 str(enum) gotcha)."""
    return enum_or_str.value if hasattr(enum_or_str, "value") else str(enum_or_str)
