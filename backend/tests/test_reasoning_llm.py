"""Tests for the LLM provider abstraction and structured-output helper."""

from __future__ import annotations

from pydantic import BaseModel

from agents.reasoning.llm import (
    LLMMessage,
    LLMProvider,
    NullLLMProvider,
    OpenAIProvider,
    generate_structured,
    get_provider,
)
from core.config import Settings


class _Schema(BaseModel):
    name: str
    count: int


class _ScriptedProvider(LLMProvider):
    """Returns queued responses in order; records how many times it was called."""

    name = "scripted"

    def __init__(self, responses: list[str]) -> None:
        self._responses = responses
        self.calls = 0

    @property
    def available(self) -> bool:
        return True

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        response = self._responses[min(self.calls, len(self._responses) - 1)]
        self.calls += 1
        return response


def test_null_provider_is_unavailable() -> None:
    assert NullLLMProvider().available is False


def test_generate_structured_returns_none_without_provider() -> None:
    result = generate_structured(
        NullLLMProvider(), system="s", user="u", schema=_Schema
    )
    assert result is None


def test_generate_structured_parses_valid_json() -> None:
    provider = _ScriptedProvider(['{"name": "a", "count": 3}'])
    result = generate_structured(provider, system="s", user="u", schema=_Schema)
    assert result == _Schema(name="a", count=3)
    assert provider.calls == 1


def test_generate_structured_retries_on_malformed_response() -> None:
    provider = _ScriptedProvider(["not json at all", '{"name": "b", "count": 5}'])
    result = generate_structured(provider, system="s", user="u", schema=_Schema, retries=2)
    assert result == _Schema(name="b", count=5)
    assert provider.calls == 2  # retried once


def test_generate_structured_extracts_json_from_prose_and_fences() -> None:
    provider = _ScriptedProvider(['Here you go:\n```json\n{"name": "c", "count": 1}\n```'])
    result = generate_structured(provider, system="s", user="u", schema=_Schema)
    assert result == _Schema(name="c", count=1)


def test_generate_structured_gives_up_after_retries() -> None:
    provider = _ScriptedProvider(["nope"])
    result = generate_structured(provider, system="s", user="u", schema=_Schema, retries=1)
    assert result is None
    assert provider.calls == 2  # initial + 1 retry


def test_get_provider_defaults_to_null() -> None:
    assert isinstance(get_provider(Settings(llm_provider="none")), NullLLMProvider)
    # Configured but no key -> still Null.
    assert isinstance(get_provider(Settings(llm_provider="openai")), NullLLMProvider)


def test_get_provider_selects_openai_when_configured() -> None:
    provider = get_provider(Settings(llm_provider="openai", llm_api_key="sk-test"))
    assert isinstance(provider, OpenAIProvider)
    assert provider.available is True
