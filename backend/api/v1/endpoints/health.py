"""Health and readiness endpoints.

- `GET /health/live`  : liveness - the process is up and serving requests.
- `GET /health/ready` : readiness - downstream dependencies are reachable.
"""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from api.dependencies import HealthServiceDep, SettingsDep
from models.schemas import (
    HealthResponse,
    HealthState,
    LivenessResponse,
    LLMHealthResponse,
)

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live", response_model=LivenessResponse, summary="Liveness probe")
async def liveness() -> LivenessResponse:
    """Return OK if the process is running. Does not touch dependencies."""
    return LivenessResponse()


@router.get("/ready", response_model=HealthResponse, summary="Readiness probe")
async def readiness(
    health_service: HealthServiceDep,
    settings: SettingsDep,
    response: Response,
) -> HealthResponse:
    """Report readiness based on downstream dependency health.

    Returns 503 when no dependency is reachable so orchestrators (Kubernetes,
    load balancers) can route traffic away from an unhealthy instance.
    """
    from importlib.metadata import PackageNotFoundError, version

    try:
        app_version = version("devops-ai-auditor-backend")
    except PackageNotFoundError:
        app_version = "0.1.0"

    result = await health_service.check(version=app_version)
    if result.status == HealthState.UNHEALTHY:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return result


@router.get("/llm", response_model=LLMHealthResponse, summary="LLM connectivity check")
async def llm_health(settings: SettingsDep) -> LLMHealthResponse:
    """Verify the configured LLM provider is reachable and the model is valid.

    Makes a tiny live completion call (so it does consume a token or two). Always
    returns 200 with a diagnostic body; `configured=false` means no provider is
    set, and `ok=false` with `detail` explains any connectivity/model error.
    """
    import asyncio
    import time

    from agents.reasoning.llm import LLMMessage, get_provider

    provider = get_provider(settings)
    if not provider.available:
        return LLMHealthResponse(
            provider=provider.name,
            model=settings.llm_model,
            configured=False,
            ok=False,
            detail="No LLM provider configured (set LLM_PROVIDER and LLM_API_KEY).",
        )

    start = time.monotonic()
    try:
        text = await asyncio.to_thread(
            provider.complete,
            [LLMMessage("user", "Reply with the single word: ok")],
            temperature=0.0,
        )
    except Exception as exc:  # noqa: BLE001 - any provider error is reported as unhealthy
        return LLMHealthResponse(
            provider=provider.name,
            model=settings.llm_model,
            configured=True,
            ok=False,
            detail=f"LLM request failed: {exc}",
            latency_ms=int((time.monotonic() - start) * 1000),
        )

    ok = bool(text.strip())
    return LLMHealthResponse(
        provider=provider.name,
        model=settings.llm_model,
        configured=True,
        ok=ok,
        detail="Model responded." if ok else "Model returned an empty response.",
        latency_ms=int((time.monotonic() - start) * 1000),
    )
