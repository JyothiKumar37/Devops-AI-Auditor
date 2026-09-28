"""Tests for the complementary AI review scanner.

Everything is verified with a fake LLM provider returning canned JSON, so no real
model or API key is needed. Covers schema mapping/clamping, the no-provider
no-op, Gemini provider selection, and end-to-end integration (AI findings surface
in the scan and are deduped against the deterministic ones).
"""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agents.ai_review.scanner import AIReviewScanner
from agents.reasoning.llm import LLMMessage, LLMProvider, NullLLMProvider, get_provider
from core.config import Settings
from main import create_app
from models.enums import Confidence, Severity


class FakeProvider(LLMProvider):
    """LLM provider that returns a fixed payload regardless of input."""

    name = "fake"

    def __init__(self, payload: str) -> None:
        self._payload = payload

    @property
    def available(self) -> bool:
        return True

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        return self._payload


def test_review_text_maps_clamps_and_filters() -> None:
    payload = json.dumps(
        {
            "findings": [
                {
                    "title": "Hardcoded admin creds",
                    "category": "security",
                    "severity": "critical",  # must clamp to high
                    "line": 10,
                    "evidence": "x" * 300,  # must truncate
                    "description": "d",
                    "recommendation": "r",
                },
                {"title": "", "category": "security", "severity": "low"},  # skipped
                {
                    "title": "Odd thing",
                    "category": "weird",  # unknown -> best_practice
                    "severity": "bogus",  # unknown -> medium
                    "line": 0,  # -> None
                },
            ]
        }
    )
    scanner = AIReviewScanner(Settings(), provider=FakeProvider(payload))
    findings = scanner.review_text("content", "config/app.yaml")

    assert len(findings) == 2  # empty-title one is dropped
    first, second = findings
    assert first.rule_id == "AI-SECURITY"
    assert first.scanner == "ai-review"
    assert first.severity is Severity.HIGH  # clamped from critical
    assert first.confidence is Confidence.MEDIUM
    assert first.line_number == 10
    assert first.evidence is not None and len(first.evidence) <= 200

    assert second.rule_id == "AI-BEST_PRACTICE"
    assert second.severity is Severity.MEDIUM
    assert second.line_number is None


def test_no_provider_is_noop() -> None:
    scanner = AIReviewScanner(Settings(), provider=NullLLMProvider())
    assert scanner.available is False
    assert scanner.analyze_repo(Path("/tmp"), ["anything.yaml"]) == []


def test_gemini_provider_selected() -> None:
    settings = Settings(  # type: ignore[arg-type]
        llm_provider="gemini", llm_api_key="secret", llm_model="gpt-4o-mini"
    )
    provider = get_provider(settings)
    assert provider.name == "gemini"
    assert provider.available is True


_DOCKERFILE = (
    b"FROM ubuntu:latest\n"  # line 1 -> DCK001
    b"RUN apt-get update\n"  # line 2 -> no rule finding
    b"ENV DB_PASSWORD=hunter2plaintext\n"  # line 3 -> DCK005
    b"USER root\n"  # line 4 -> DCK003
)

# One AI finding on an un-flagged line (kept) and one on a rule-flagged line
# (must be deduped away).
_AI_PAYLOAD = json.dumps(
    {
        "findings": [
            {
                "title": "Non-reproducible apt update",
                "category": "reliability",
                "severity": "critical",
                "line": 2,
                "evidence": "RUN apt-get update",
                "description": "d",
                "recommendation": "Pin versions.",
            },
            {
                "title": "Root user",
                "category": "security",
                "severity": "high",
                "line": 4,  # same as DCK003 -> should be deduped
                "evidence": "USER root",
                "description": "d",
                "recommendation": "Use a non-root user.",
            },
        ]
    }
)


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(  # type: ignore[arg-type]
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        workspace_root=str(tmp_path / "ws"),
        ai_scan_enabled=True,
    )
    app = create_app(settings=settings)
    with TestClient(app) as test_client:
        yield test_client


class _BoomProvider(FakeProvider):
    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        raise RuntimeError("connection refused")


def test_llm_health_no_provider(client: TestClient) -> None:
    body = client.get("/api/v1/health/llm").json()
    assert body["configured"] is False
    assert body["ok"] is False


def test_llm_health_ok(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agents.reasoning.llm.get_provider", lambda _s: FakeProvider("ok"))
    body = client.get("/api/v1/health/llm").json()
    assert body["configured"] is True
    assert body["ok"] is True
    assert body["latency_ms"] is not None


def test_llm_health_reports_errors(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agents.reasoning.llm.get_provider", lambda _s: _BoomProvider(""))
    body = client.get("/api/v1/health/llm").json()
    assert body["configured"] is True
    assert body["ok"] is False
    assert "failed" in body["detail"].lower()


def test_ai_findings_surface_and_dedupe(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "agents.ai_review.scanner.get_provider", lambda _s: FakeProvider(_AI_PAYLOAD)
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Dockerfile", _DOCKERFILE)
    scan_id = client.post(
        "/api/v1/scans/upload",
        files={"file": ("repo.zip", buffer.getvalue(), "application/zip")},
    ).json()["id"]

    items = client.get(f"/api/v1/scans/{scan_id}/findings").json()["items"]
    ai = [f for f in items if f["scanner"] == "ai-review"]

    # The un-flagged-line finding surfaced, mapped + clamped.
    kept = [f for f in ai if f["line_number"] == 2]
    assert len(kept) == 1
    assert kept[0]["rule_id"] == "AI-RELIABILITY"
    assert kept[0]["severity"] == "high"  # clamped from critical

    # The finding on line 4 collided with DCK003 (USER root) and was deduped.
    assert all(f["line_number"] != 4 for f in ai)
    # ...while the deterministic finding on line 4 is still present.
    assert any(f["rule_id"] == "DCK003" for f in items)
