"""AI review scanner.

A complementary, LLM-backed pass that reads DevOps files and reports issues the
deterministic rules may miss (context-specific misconfigurations, risky logic,
insecure defaults). It is best-effort and clearly bounded:

- Runs only when an LLM provider is configured (otherwise a no-op).
- Emits findings with ``scanner="ai-review"`` at capped confidence and never
  above HIGH severity - the rule engine stays the reproducible source of truth.
- Asks the model for strict JSON validated against a schema; any provider or
  parse failure yields no findings rather than raising (a scan never breaks
  because of the AI pass).

Findings are not auto-remediated (guidance only), and callers dedupe them
against the deterministic findings.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from agents.reasoning.llm import LLMProvider, generate_structured, get_provider
from core.config import Settings
from core.logging import get_logger
from models.enums import Confidence, FindingCategory, Severity
from scanners.finding import RuleFinding

logger = get_logger(__name__)

_MAX_EVIDENCE = 200
_MAX_FINDINGS_PER_FILE = 8
# The AI layer never asserts higher than HIGH; CRITICAL stays the rule engine's call.
_MAX_SEVERITY_RANK = Severity.HIGH.rank

_SYSTEM_PROMPT = (
    "You are a senior DevOps security reviewer analysing one configuration or "
    "infrastructure file. Report concrete, high-signal problems a careful reviewer "
    "would flag: security misconfigurations, insecure defaults, reliability and "
    "supply-chain risks, and clear best-practice violations. Prefer precision over "
    "recall: do not invent issues and do not report trivial style nits.\n\n"
    "Respond with ONLY a JSON object of the form:\n"
    '{"findings": [{"title": str, "category": one of [security, secrets, '
    "reliability, efficiency, supply_chain, best_practice, configuration], "
    '"severity": one of [low, medium, high], "line": int|null, "evidence": '
    'str|null, "description": str, "recommendation": str}]}\n'
    "Use the 1-based line number where the issue occurs when you can. Return an "
    "empty findings list if the file has no real problems."
)


class _AIFinding(BaseModel):
    title: str = ""
    category: str = "best_practice"
    severity: str = "medium"
    line: int | None = None
    evidence: str | None = None
    description: str = ""
    recommendation: str = ""


class _AIFindings(BaseModel):
    findings: list[_AIFinding] = Field(default_factory=list)


def _map_category(value: str) -> FindingCategory:
    try:
        return FindingCategory(value.strip().lower())
    except ValueError:
        return FindingCategory.BEST_PRACTICE


def _map_severity(value: str) -> Severity:
    try:
        severity = Severity(value.strip().lower())
    except ValueError:
        return Severity.MEDIUM
    return severity if severity.rank <= _MAX_SEVERITY_RANK else Severity.HIGH


class AIReviewScanner:
    """Runs an LLM review over files and returns findings (best-effort)."""

    scanner_name = "ai-review"

    def __init__(self, settings: Settings, provider: LLMProvider | None = None) -> None:
        self._settings = settings
        self._provider = provider or get_provider(settings)
        self._max_files = settings.ai_scan_max_files
        self._max_bytes = settings.ai_scan_max_file_bytes

    @property
    def available(self) -> bool:
        return self._provider.available

    def review_text(self, text: str, file_path: str) -> list[RuleFinding]:
        """Review a single file's text and return AI findings (IO-free)."""
        result = generate_structured(
            self._provider,
            system=_SYSTEM_PROMPT,
            user=f"File: {file_path}\n\n{text}",
            schema=_AIFindings,
            temperature=0.0,
        )
        if result is None:
            return []
        findings: list[RuleFinding] = []
        for item in result.findings[:_MAX_FINDINGS_PER_FILE]:
            title = item.title.strip()
            if not title:
                continue
            category = _map_category(item.category)
            evidence = (item.evidence or "").strip()[:_MAX_EVIDENCE]
            findings.append(
                RuleFinding(
                    rule_id=f"AI-{category.value.upper()}",
                    scanner=self.scanner_name,
                    category=category,
                    severity=_map_severity(item.severity),
                    confidence=Confidence.MEDIUM,
                    title=title,
                    description=item.description.strip() or title,
                    recommendation=item.recommendation.strip(),
                    file_path=file_path,
                    line_number=item.line if item.line and item.line > 0 else None,
                    evidence=evidence or None,
                )
            )
        return findings

    def analyze_repo(self, repo_root: Path, paths: list[str]) -> list[RuleFinding]:
        """Review up to `ai_scan_max_files` files on disk; never raises."""
        findings: list[RuleFinding] = []
        for path in paths[: self._max_files]:
            abs_path = repo_root / path
            try:
                text = abs_path.read_text(encoding="utf-8", errors="ignore")[
                    : self._max_bytes
                ]
            except OSError as exc:
                logger.warning("ai_review_read_failed", path=path, error=str(exc))
                continue
            try:
                findings.extend(self.review_text(text, path))
            except Exception as exc:  # noqa: BLE001 - best-effort; never break a scan
                logger.warning("ai_review_failed", path=path, error=str(exc))
        return findings
