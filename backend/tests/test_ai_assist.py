"""Tests for the interactive AI assistance features (fake LLM provider)."""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agents.reasoning.llm import LLMMessage, LLMProvider
from core.config import Settings
from main import create_app

_DOCKERFILE = b"FROM ubuntu:latest\nRUN apt-get update\nUSER root\n"


class FakeProvider(LLMProvider):
    name = "fake"

    def __init__(self, payload: str) -> None:
        self._payload = payload

    @property
    def available(self) -> bool:
        return True

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        return self._payload


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(  # type: ignore[arg-type]
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        workspace_root=str(tmp_path / "ws"),
    )
    app = create_app(settings=settings)
    with TestClient(app) as test_client:
        yield test_client


def _use_fake(monkeypatch: pytest.MonkeyPatch, payload: str) -> None:
    monkeypatch.setattr(
        "agents.ai_assist.service.get_provider", lambda _s: FakeProvider(payload)
    )


def _scan_with_findings(client: TestClient) -> tuple[str, list[dict]]:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Dockerfile", _DOCKERFILE)
    scan_id = client.post(
        "/api/v1/scans/upload",
        files={"file": ("repo.zip", buffer.getvalue(), "application/zip")},
    ).json()["id"]
    items = client.get(f"/api/v1/scans/{scan_id}/findings").json()["items"]
    return scan_id, items


def test_explain_finding(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id, items = _scan_with_findings(client)
    _use_fake(monkeypatch, json.dumps({"explanation": "Running as root is risky because..."}))
    resp = client.post(
        f"/api/v1/scans/{scan_id}/findings/{items[0]['id']}/explain"
    )
    assert resp.status_code == 200
    assert "root" in resp.json()["explanation"].lower()


def test_fix_suggestion(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id, items = _scan_with_findings(client)
    fixed = "FROM python:3.11-slim\nRUN apt-get update\nUSER app\n"
    _use_fake(monkeypatch, json.dumps({"fixed_content": fixed, "explanation": "Use non-root."}))
    resp = client.post(
        f"/api/v1/scans/{scan_id}/findings/{items[0]['id']}/fix-suggestion"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["changed"] is True
    assert "USER app" in body["after"]
    assert body["diff"]  # a unified diff was produced


def test_triage_finding(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id, items = _scan_with_findings(client)
    _use_fake(
        monkeypatch,
        json.dumps({"likely_false_positive": True, "confidence": "high", "reason": "example dir"}),
    )
    resp = client.post(
        f"/api/v1/scans/{scan_id}/findings/{items[0]['id']}/triage"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["likely_false_positive"] is True
    assert body["confidence"] == "high"


def test_scan_summary(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id, _ = _scan_with_findings(client)
    _use_fake(monkeypatch, json.dumps({"summary": "The image runs as root and uses latest."}))
    resp = client.get(f"/api/v1/scans/{scan_id}/ai-summary")
    assert resp.status_code == 200
    assert resp.json()["summary"]


def test_priorities(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id, items = _scan_with_findings(client)
    target = items[0]["id"]
    _use_fake(
        monkeypatch,
        json.dumps({"items": [{"finding_id": target, "rationale": "highest blast radius"}]}),
    )
    resp = client.get(f"/api/v1/scans/{scan_id}/priorities")
    assert resp.status_code == 200
    result = resp.json()["items"]
    assert result and result[0]["finding_id"] == target
    assert result[0]["rationale"] == "highest blast radius"
    assert result[0]["rule_id"]  # enriched from the finding


def test_ask(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id, _ = _scan_with_findings(client)
    _use_fake(monkeypatch, json.dumps({"answer": "Your biggest risk is running as root."}))
    resp = client.post(f"/api/v1/scans/{scan_id}/ask", json={"question": "biggest risk?"})
    assert resp.status_code == 200
    assert "root" in resp.json()["answer"].lower()


def test_chat_persists_history_and_clears(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_id, _ = _scan_with_findings(client)

    # Empty to start.
    assert client.get(f"/api/v1/scans/{scan_id}/chat").json()["messages"] == []

    _use_fake(monkeypatch, json.dumps({"answer": "Your biggest risk is running as root."}))
    first = client.post(
        f"/api/v1/scans/{scan_id}/chat", json={"question": "biggest risk?"}
    ).json()
    # User question then assistant answer, in order.
    assert [m["role"] for m in first["messages"]] == ["user", "assistant"]
    assert first["messages"][0]["content"] == "biggest risk?"
    assert "root" in first["messages"][1]["content"].lower()

    _use_fake(monkeypatch, json.dumps({"answer": "Set USER to a non-root account."}))
    second = client.post(
        f"/api/v1/scans/{scan_id}/chat", json={"question": "how do I fix it?"}
    ).json()
    # History accumulates.
    assert [m["role"] for m in second["messages"]] == [
        "user",
        "assistant",
        "user",
        "assistant",
    ]

    # Reloading returns the same persisted history.
    reloaded = client.get(f"/api/v1/scans/{scan_id}/chat").json()
    assert len(reloaded["messages"]) == 4

    # Clearing wipes it.
    assert client.delete(f"/api/v1/scans/{scan_id}/chat").status_code == 204
    assert client.get(f"/api/v1/scans/{scan_id}/chat").json()["messages"] == []


def test_chat_requires_provider(client: TestClient) -> None:
    scan_id, _ = _scan_with_findings(client)
    # Reading history is fine without a provider; posting needs one.
    assert client.get(f"/api/v1/scans/{scan_id}/chat").status_code == 200
    resp = client.post(f"/api/v1/scans/{scan_id}/chat", json={"question": "hi"})
    assert resp.status_code == 503
    # A failed post must not persist anything.
    assert client.get(f"/api/v1/scans/{scan_id}/chat").json()["messages"] == []


def test_ai_endpoints_require_provider(client: TestClient) -> None:
    # No provider configured (default) and no monkeypatch -> 503 everywhere.
    scan_id, items = _scan_with_findings(client)
    fid = items[0]["id"]
    assert client.post(f"/api/v1/scans/{scan_id}/findings/{fid}/explain").status_code == 503
    assert client.get(f"/api/v1/scans/{scan_id}/ai-summary").status_code == 503
    assert client.post(
        f"/api/v1/scans/{scan_id}/ask", json={"question": "x"}
    ).status_code == 503
