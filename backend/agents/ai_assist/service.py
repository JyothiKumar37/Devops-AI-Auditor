"""LLM-backed assistance over a completed scan.

Groups the interactive AI features that operate on a scan's stored data:

- ``explain_finding``   - a plain-language deep dive on one finding.
- ``suggest_fix``       - an AI-proposed patch (review-only; never auto-applied).
- ``triage_finding``    - a false-positive likelihood assessment.
- ``summarize_scan``    - a short executive summary of the whole scan.
- ``prioritize``        - context-aware re-ranking of findings by real risk.
- ``ask``               - a grounded Q&A over the scan's findings.

Every operation is grounded in the scan's persisted findings/files (to curb
hallucination), gated on a configured LLM provider (honouring the runtime model
override), and best-effort: a transient/parse failure raises a retryable error
rather than corrupting anything. Nothing here mutates the scan or applies fixes.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import TypeVar

from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.reasoning.llm import LLMProvider, generate_structured, get_provider
from core.config import Settings
from core.exceptions import AppError, NotFoundError
from models.chat import ChatMessage
from models.enums import Severity
from models.finding import Finding
from models.scan import RepositoryFile, Scan
from services.remediation import build_diff
from services.runtime_config import resolve_settings

_MAX_HISTORY_TURNS = 10

_MAX_FILE_BYTES = 8000
_MAX_SNIPPET_LINES = 40
_MAX_FINDINGS = 60

_T = TypeVar("_T", bound=BaseModel)


class LLMUnavailableError(AppError):
    status_code = 503
    code = "llm_unavailable"


class LLMRequestFailedError(AppError):
    status_code = 502
    code = "llm_request_failed"


# ---- structured LLM output schemas ----------------------------------------


class _Explanation(BaseModel):
    explanation: str = ""


class _Fix(BaseModel):
    fixed_content: str = ""
    explanation: str = ""


class _Triage(BaseModel):
    likely_false_positive: bool = False
    confidence: str = "medium"
    reason: str = ""


class _Summary(BaseModel):
    summary: str = ""


class _PriorityItem(BaseModel):
    finding_id: str
    rationale: str = ""


class _Priorities(BaseModel):
    items: list[_PriorityItem] = Field(default_factory=list)


class _Answer(BaseModel):
    answer: str = ""


class AiAssistService:
    """Interactive LLM features grounded in a scan's stored data."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    async def _provider(self) -> LLMProvider:
        provider = get_provider(await resolve_settings(self._session, self._settings))
        if not provider.available:
            raise LLMUnavailableError(
                "No LLM provider is configured. Set LLM_PROVIDER and LLM_API_KEY."
            )
        return provider

    def _generate(
        self, provider: LLMProvider, system: str, user: str, schema: type[_T]
    ) -> _T:
        result = generate_structured(provider, system=system, user=user, schema=schema)
        if result is None:
            raise LLMRequestFailedError(
                "The model did not return a valid response. Please try again."
            )
        return result

    async def _get_scan(self, scan_id: uuid.UUID) -> Scan:
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")
        return scan

    async def _load_finding(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID
    ) -> tuple[Finding, str, str | None]:
        finding = await self._session.get(Finding, finding_id)
        if finding is None or finding.scan_id != scan_id:
            raise NotFoundError(f"Finding {finding_id} not found for scan {scan_id}.")
        path, content = "", None
        if finding.file_id is not None:
            repo_file = await self._session.get(RepositoryFile, finding.file_id)
            if repo_file is not None:
                path, content = repo_file.path, repo_file.content
        return finding, path, content

    async def _load_findings(
        self, scan_id: uuid.UUID, limit: int = _MAX_FINDINGS
    ) -> list[tuple[Finding, str | None]]:
        rows = (
            await self._session.execute(
                select(Finding, RepositoryFile.path)
                .outerjoin(RepositoryFile, Finding.file_id == RepositoryFile.id)
                .where(Finding.scan_id == scan_id)
            )
        ).all()
        items = [(row[0], row[1]) for row in rows]
        items.sort(key=lambda it: -Severity(it[0].severity).rank)
        return items[:limit]

    @staticmethod
    def _finding_block(finding: Finding, path: str | None) -> str:
        loc = f"{path or '(unknown file)'}:{finding.line_number or '?'}"
        return (
            f"- id={finding.id} rule={finding.rule_id} severity={finding.severity} "
            f"category={finding.category} title={finding.title!r} at {loc}"
        )

    @staticmethod
    def _snippet(content: str | None, line: int | None) -> str:
        if not content:
            return "(file content not available)"
        lines = content.splitlines()
        if line and line > 0:
            start = max(0, line - _MAX_SNIPPET_LINES // 2)
            end = min(len(lines), start + _MAX_SNIPPET_LINES)
            window = lines[start:end]
            return "\n".join(f"{start + i + 1}: {t}" for i, t in enumerate(window))
        return "\n".join(lines[:_MAX_SNIPPET_LINES])

    # ---- operations --------------------------------------------------------

    async def explain_finding(self, scan_id: uuid.UUID, finding_id: uuid.UUID) -> str:
        provider = await self._provider()
        finding, path, content = await self._load_finding(scan_id, finding_id)
        system = (
            "You are a senior DevOps security engineer. Explain ONE finding for the "
            "engineer who will fix it: why it matters here, a realistic impact/exploit "
            "scenario, and the concrete fix. Be specific and concise (markdown). "
            'Respond ONLY as JSON: {"explanation": "..."}.'
        )
        user = (
            f"Finding: {finding.title}\nRule: {finding.rule_id} ({finding.scanner})\n"
            f"Severity: {finding.severity}  Category: {finding.category}\n"
            f"File: {path or '(unknown)'}  Line: {finding.line_number or '?'}\n"
            f"Description: {finding.description}\n"
            f"Evidence: {finding.evidence or '(none)'}\n"
            f"Rule recommendation: {finding.recommendation or '(none)'}\n\n"
            f"Relevant file snippet:\n{self._snippet(content, finding.line_number)}"
        )
        return self._generate(provider, system, user, _Explanation).explanation.strip()

    async def suggest_fix(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID
    ) -> dict[str, object]:
        provider = await self._provider()
        finding, path, content = await self._load_finding(scan_id, finding_id)
        if not content:
            raise LLMRequestFailedError(
                "The file content is not stored, so a fix cannot be suggested."
            )
        original = content[:_MAX_FILE_BYTES]
        system = (
            "You are a senior DevOps engineer. Given a file and ONE finding, return the "
            "corrected FULL file content that resolves the finding while preserving all "
            "other behaviour and formatting. If you cannot safely fix it, return the "
            "original content unchanged and explain why. Respond ONLY as JSON: "
            '{"fixed_content": "<entire file>", "explanation": "..."}.'
        )
        user = (
            f"Finding: {finding.title} (rule {finding.rule_id}, severity {finding.severity})\n"
            f"File: {path}\nLine: {finding.line_number or '?'}\n"
            f"Recommendation: {finding.recommendation or '(none)'}\n\n"
            f"Current file content:\n{original}"
        )
        result = self._generate(provider, system, user, _Fix)
        fixed = result.fixed_content
        changed = bool(fixed) and fixed != original
        return {
            "file_path": path,
            "before": original,
            "after": fixed if changed else original,
            "diff": build_diff(path or "file", original, fixed) if changed else "",
            "explanation": result.explanation.strip(),
            "changed": changed,
        }

    async def triage_finding(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID
    ) -> dict[str, object]:
        provider = await self._provider()
        finding, path, content = await self._load_finding(scan_id, finding_id)
        system = (
            "Assess whether this static-analysis finding is likely a FALSE POSITIVE in "
            "context (e.g. a test/example/template file, an intentional and safe usage, "
            "or not actually exploitable). Be conservative: only say likely false "
            'positive when the evidence supports it. Respond ONLY as JSON: '
            '{"likely_false_positive": bool, "confidence": "low|medium|high", "reason": "..."}.'
        )
        user = (
            f"Finding: {finding.title}\nRule: {finding.rule_id}  Severity: {finding.severity}\n"
            f"File: {path or '(unknown)'}  Line: {finding.line_number or '?'}\n"
            f"Evidence: {finding.evidence or '(none)'}\n\n"
            f"Relevant file snippet:\n{self._snippet(content, finding.line_number)}"
        )
        result = self._generate(provider, system, user, _Triage)
        confidence = result.confidence.strip().lower()
        if confidence not in {"low", "medium", "high"}:
            confidence = "medium"
        return {
            "likely_false_positive": bool(result.likely_false_positive),
            "confidence": confidence,
            "reason": result.reason.strip(),
        }

    async def summarize_scan(self, scan_id: uuid.UUID) -> str:
        provider = await self._provider()
        scan = await self._get_scan(scan_id)
        findings = await self._load_findings(scan_id)
        counts: dict[str, int] = {}
        for finding, _ in findings:
            counts[str(finding.severity)] = counts.get(str(finding.severity), 0) + 1
        top = "\n".join(self._finding_block(f, p) for f, p in findings[:10]) or "(none)"
        system = (
            "Write a concise executive summary of a DevOps audit for a busy engineer or "
            "manager: the overall risk posture, the most important issues, and what to "
            "fix first. About 120 words, markdown. Respond ONLY as JSON: "
            '{"summary": "..."}.'
        )
        user = (
            f"Repository: {scan.repository_name}\n"
            f"Severity counts: {counts}\n\n"
            f"Top findings:\n{top}"
        )
        return self._generate(provider, system, user, _Summary).summary.strip()

    async def prioritize(self, scan_id: uuid.UUID) -> list[dict[str, object]]:
        provider = await self._provider()
        await self._get_scan(scan_id)
        findings = await self._load_findings(scan_id)
        if not findings:
            return []
        by_id = {str(f.id): (f, p) for f, p in findings}
        listing = "\n".join(self._finding_block(f, p) for f, p in findings)
        system = (
            "Re-rank these DevOps findings by real-world risk for THIS repository, "
            "considering exploitability and blast radius - not just nominal severity. "
            "Order most-urgent first and give a one-line rationale each. Only use "
            'finding ids from the input. Respond ONLY as JSON: '
            '{"items": [{"finding_id": "...", "rationale": "..."}]}.'
        )
        result = self._generate(provider, system, listing, _Priorities)
        ordered: list[dict[str, object]] = []
        seen: set[str] = set()
        for item in result.items:
            entry = by_id.get(item.finding_id)
            if entry is None or item.finding_id in seen:
                continue
            seen.add(item.finding_id)
            finding, path = entry
            ordered.append(
                {
                    "finding_id": item.finding_id,
                    "rule_id": finding.rule_id,
                    "severity": str(finding.severity),
                    "title": finding.title,
                    "file": path,
                    "rationale": item.rationale.strip(),
                }
            )
        return ordered

    async def ask(self, scan_id: uuid.UUID, question: str) -> str:
        provider = await self._provider()
        scan = await self._get_scan(scan_id)
        findings = await self._load_findings(scan_id)
        listing = "\n".join(self._finding_block(f, p) for f, p in findings) or "(none)"
        system = (
            "You are a DevOps audit assistant. Answer the user's question using ONLY the "
            "provided findings for this repository. If the answer is not in the data, say "
            "so plainly. Be concise and practical (markdown). Respond ONLY as JSON: "
            '{"answer": "..."}.'
        )
        user = (
            f"Repository: {scan.repository_name}\n\n"
            f"Findings:\n{listing}\n\n"
            f"Question: {question.strip()}"
        )
        return self._generate(provider, system, user, _Answer).answer.strip()

    # ---- persistent chat ---------------------------------------------------

    async def list_chat(self, scan_id: uuid.UUID) -> list[ChatMessage]:
        """Return the scan's chat history in chronological order."""
        await self._get_scan(scan_id)
        rows = await self._session.scalars(
            select(ChatMessage)
            .where(ChatMessage.scan_id == scan_id)
            .order_by(ChatMessage.created_at.asc())
        )
        return list(rows.all())

    async def clear_chat(self, scan_id: uuid.UUID) -> None:
        """Delete the scan's chat history."""
        await self._get_scan(scan_id)
        await self._session.execute(
            delete(ChatMessage).where(ChatMessage.scan_id == scan_id)
        )
        await self._session.commit()

    async def post_chat(self, scan_id: uuid.UUID, question: str) -> list[ChatMessage]:
        """Answer a question with prior turns for context, persist both messages.

        The answer is generated first; only on success are the user question and
        the reply stored, so a provider failure never leaves a dangling turn.
        """
        provider = await self._provider()
        scan = await self._get_scan(scan_id)
        history = await self.list_chat(scan_id)
        findings = await self._load_findings(scan_id)
        listing = "\n".join(self._finding_block(f, p) for f, p in findings) or "(none)"

        transcript = "\n".join(
            f"{m.role.capitalize()}: {m.content}" for m in history[-_MAX_HISTORY_TURNS:]
        )
        system = (
            "You are a DevOps audit assistant having a conversation about ONE "
            "repository's scan. Answer the latest question using ONLY the provided "
            "findings and the prior conversation. If the answer is not in the data, "
            "say so plainly. Be concise and practical (markdown). Respond ONLY as "
            'JSON: {"answer": "..."}.'
        )
        user = (
            f"Repository: {scan.repository_name}\n\n"
            f"Findings:\n{listing}\n\n"
            f"Conversation so far:\n{transcript or '(none)'}\n\n"
            f"Latest question: {question.strip()}"
        )
        answer = self._generate(provider, system, user, _Answer).answer.strip()

        now = datetime.now(UTC)
        self._session.add(
            ChatMessage(
                id=uuid.uuid4(),
                scan_id=scan_id,
                role="user",
                content=question.strip(),
                created_at=now,
            )
        )
        self._session.add(
            ChatMessage(
                id=uuid.uuid4(),
                scan_id=scan_id,
                role="assistant",
                content=answer,
                created_at=now + timedelta(microseconds=1),
            )
        )
        await self._session.commit()
        return await self.list_chat(scan_id)
