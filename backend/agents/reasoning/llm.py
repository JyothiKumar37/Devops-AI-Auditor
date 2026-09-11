"""LLM provider abstraction and structured-output helper.

The reasoning layer talks to models only through `LLMProvider`, so the concrete
model can be swapped (OpenAI, Anthropic, a local server, ...) without touching
the agents. When no provider is configured, `NullLLMProvider` reports
`available = False` and the agents use their deterministic, evidence-grounded
fallbacks instead.

`generate_structured` parses the model's text into a Pydantic schema and retries
with a repair instruction when the response is malformed.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from core.config import Settings
from core.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T", bound=BaseModel)


@dataclass(frozen=True, slots=True)
class LLMMessage:
    role: str  # "system" | "user" | "assistant"
    content: str


class LLMProvider(ABC):
    """Abstract chat-completion provider."""

    name: str = "abstract"

    @property
    @abstractmethod
    def available(self) -> bool:
        """True if the provider can service requests."""

    @abstractmethod
    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        """Return the model's text completion for a chat conversation."""


class NullLLMProvider(LLMProvider):
    """No-op provider used when no LLM is configured."""

    name = "none"

    @property
    def available(self) -> bool:
        return False

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        raise RuntimeError("NullLLMProvider cannot complete requests.")


class OpenAIProvider(LLMProvider):
    """OpenAI (and OpenAI-compatible) chat completions via HTTP."""

    name = "openai"

    def __init__(self, api_key: str, model: str, base_url: str = "", timeout: int = 60) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self._timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        response = httpx.post(
            f"{self._base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self._api_key}"},
            json={
                "model": self._model,
                "temperature": temperature,
                "messages": [{"role": m.role, "content": m.content} for m in messages],
                "response_format": {"type": "json_object"},
            },
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]


class AnthropicProvider(LLMProvider):
    """Anthropic Messages API via HTTP."""

    name = "anthropic"

    def __init__(self, api_key: str, model: str, base_url: str = "", timeout: int = 60) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = (base_url or "https://api.anthropic.com/v1").rstrip("/")
        self._timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.0) -> str:
        system = "\n".join(m.content for m in messages if m.role == "system")
        turns = [
            {"role": m.role, "content": m.content} for m in messages if m.role != "system"
        ]
        response = httpx.post(
            f"{self._base_url}/messages",
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": self._model,
                "max_tokens": 4096,
                "temperature": temperature,
                "system": system,
                "messages": turns,
            },
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json()["content"][0]["text"]


def _safe_base_url(base_url: str) -> str:
    """Only accept an http(s) base URL; ignore anything else (SSRF hygiene).

    The base URL is operator-configured, but validating the scheme prevents
    typos or hostile config from redirecting model traffic to non-HTTP targets
    (e.g. file:// or gopher://).
    """
    url = (base_url or "").strip()
    if url and not url.lower().startswith(("http://", "https://")):
        logger.warning("llm_base_url_rejected", base_url=url)
        return ""
    return url


def get_provider(settings: Settings) -> LLMProvider:
    """Construct the configured provider, or a NullLLMProvider if unavailable."""
    provider = (settings.llm_provider or "none").lower()
    base_url = _safe_base_url(settings.llm_base_url)
    if provider == "openai" and settings.llm_api_key:
        return OpenAIProvider(
            settings.llm_api_key, settings.llm_model, base_url, settings.llm_timeout
        )
    if provider == "anthropic" and settings.llm_api_key:
        return AnthropicProvider(
            settings.llm_api_key, settings.llm_model, base_url, settings.llm_timeout
        )
    return NullLLMProvider()


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", re.DOTALL)


def _extract_json(text: str) -> str:
    """Best-effort extraction of a JSON object/array from model text."""
    fenced = _JSON_FENCE_RE.search(text)
    if fenced:
        return fenced.group(1)
    start = min(
        (i for i in (text.find("{"), text.find("[")) if i != -1),
        default=-1,
    )
    if start != -1:
        end = max(text.rfind("}"), text.rfind("]"))
        if end > start:
            return text[start : end + 1]
    return text.strip()


def generate_structured(
    provider: LLMProvider,
    *,
    system: str,
    user: str,
    schema: type[T],
    retries: int = 2,
    temperature: float = 0.0,
) -> T | None:
    """Call the provider and parse the response into `schema`, retrying on error.

    Returns None if the provider is unavailable or every attempt fails, so the
    caller can fall back to deterministic reasoning.
    """
    if not provider.available:
        return None

    messages = [LLMMessage("system", system), LLMMessage("user", user)]
    for attempt in range(retries + 1):
        try:
            raw = provider.complete(messages, temperature=temperature)
        except httpx.HTTPError as exc:
            logger.warning("llm_request_failed", attempt=attempt, error=str(exc))
            break
        try:
            return schema.model_validate_json(_extract_json(raw))
        except (ValidationError, json.JSONDecodeError, ValueError) as exc:
            logger.warning("llm_structured_parse_failed", attempt=attempt, error=str(exc))
            messages.append(LLMMessage("assistant", raw))
            messages.append(
                LLMMessage(
                    "user",
                    "Your previous response was not valid JSON for the required schema. "
                    "Respond with ONLY a single JSON object matching the schema, no prose.",
                )
            )
    return None
