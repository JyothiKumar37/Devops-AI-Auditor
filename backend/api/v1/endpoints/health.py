"""Health and readiness endpoints.

- `GET /health/live`  : liveness - the process is up and serving requests.
- `GET /health/ready` : readiness - downstream dependencies are reachable.
"""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from api.dependencies import HealthServiceDep, SettingsDep
from models.schemas import HealthResponse, HealthState, LivenessResponse

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
