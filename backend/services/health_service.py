"""Health aggregation service.

Reports application readiness by probing downstream dependencies (PostgreSQL and
Redis) concurrently. The overall state is derived from the component states so
callers get a single actionable status plus per-component detail.
"""

from __future__ import annotations

import asyncio

from core.config import Settings
from core.database import Database
from core.redis import RedisClient
from models.schemas import ComponentHealth, HealthResponse, HealthState


class HealthService:
    """Aggregates the health of the application's downstream dependencies."""

    def __init__(self, settings: Settings, database: Database, redis: RedisClient) -> None:
        self._settings = settings
        self._database = database
        self._redis = redis

    async def check(self, version: str) -> HealthResponse:
        """Probe all dependencies concurrently and build a health response."""
        db_ok, redis_ok = await asyncio.gather(
            self._database.ping(),
            self._redis.ping(),
        )

        components = [
            self._component("postgres", db_ok),
            self._component("redis", redis_ok),
        ]

        return HealthResponse(
            status=self._overall_state(components),
            version=version,
            environment=self._settings.environment.value,
            components=components,
        )

    @staticmethod
    def _component(name: str, ok: bool) -> ComponentHealth:
        return ComponentHealth(
            name=name,
            state=HealthState.HEALTHY if ok else HealthState.UNHEALTHY,
            detail=None if ok else "unreachable",
        )

    @staticmethod
    def _overall_state(components: list[ComponentHealth]) -> HealthState:
        states = {c.state for c in components}
        if states == {HealthState.HEALTHY}:
            return HealthState.HEALTHY
        if HealthState.HEALTHY in states:
            return HealthState.DEGRADED
        return HealthState.UNHEALTHY
