"""Reusable, grounded AI review core (non-authoritative).

Produces :class:`AIReviewItem` observations about risks the deterministic rules
may miss (architectural, config-interaction, deployment, reliability, security
design). Shared by the PR review (M7) and the security review agent (M8).

Guarantees:
- Items are grounded: each must reference at least one real candidate file;
  items that cite no real file are dropped (hallucination guard).
- Items are bounded and secret-redacted/neutralized.
- Items are always ``source="AI_REVIEW"``, ``authoritative=False`` - they can
  never fail CI, policy, or a deployment gate.
"""

from __future__ import annotations

import asyncio
from typing import Any

from pydantic import BaseModel, Field

from agents.investigation.schemas import AIReviewItem
from agents.reasoning.llm import LLMProvider, generate_structured
from agents.reasoning.sanitize import guardrail_system, neutralize, wrap_untrusted
from core.logging import get_logger
from models.enums import FindingCategory

logger = get_logger(__name__)

_VALID_CONFIDENCE = {"low", "medium", "high"}


class _ReviewItem(BaseModel):
    title: str = ""
    concern: str = ""
    category: str = "security"
    confidence: str = "low"
    files: list[str] = Field(default_factory=list)


class _ReviewItems(BaseModel):
    items: list[_ReviewItem] = Field(default_factory=list)


def _map_category(value: str) -> str:
    try:
        return FindingCategory(value.strip().lower()).value
    except ValueError:
        return FindingCategory.SECURITY.value


async def run_review(
    provider: LLMProvider,
    *,
    role: str,
    instructions: str,
    repo_name: str,
    findings: list[dict[str, Any]],
    candidate_files: set[str],
    max_items: int = 8,
) -> list[AIReviewItem]:
    """Run one grounded AI review pass; returns [] if AI is unavailable/failed."""
    if not provider.available:
        return []

    system = guardrail_system(role) + "\n" + instructions + (
        "\nRules:\n"
        "- Only raise concerns a careful reviewer would flag that the "
        "deterministic findings below do NOT already cover.\n"
        "- Every item MUST reference at least one file from the candidate file "
        "list; use exact paths.\n"
        "- Prefer precision over recall; do not invent files, findings, or facts.\n"
        '- Respond ONLY as JSON {"items": [{"title": str, "concern": str, '
        '"category": one of [security, secrets, reliability, efficiency, '
        'supply_chain, best_practice, configuration], "confidence": '
        '"low|medium|high", "files": [str]}]}.'
    )
    payload = {
        "repository": neutralize(repo_name, max_length=200),
        "deterministic_findings": findings[:40],
        "candidate_files": sorted(candidate_files)[:60],
    }
    import json

    user = (
        "Review the following deterministic scan context and candidate files.\n\n"
        + wrap_untrusted(json.dumps(payload, default=str)[:7000])
    )
    result = await asyncio.to_thread(
        generate_structured, provider, system=system, user=user, schema=_ReviewItems
    )
    if result is None:
        return []

    items: list[AIReviewItem] = []
    for raw in result.items[:max_items]:
        title = neutralize(raw.title, max_length=200).strip()
        if not title:
            continue
        real_files = [f for f in raw.files if f in candidate_files]
        if not real_files:
            # Hallucination guard: no real file reference -> drop.
            continue
        confidence = raw.confidence.strip().lower()
        if confidence not in _VALID_CONFIDENCE:
            confidence = "low"
        items.append(
            AIReviewItem(
                title=title,
                concern=neutralize(raw.concern, max_length=600),
                category=_map_category(raw.category),
                confidence=confidence,
                files=sorted(set(real_files))[:10],
            )
        )
    return items
