"""Async Redis client wrapper.

Used for caching and as the message broker/result backend for background
workers. Like the database layer, the client connects lazily and health checks
never raise.
"""

from __future__ import annotations

from redis.asyncio import Redis

from core.config import Settings
from core.logging import get_logger

logger = get_logger(__name__)


class RedisClient:
    """Owns a single async Redis connection pool for the application lifecycle."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: Redis | None = None

    @property
    def client(self) -> Redis:
        if self._client is None:
            self._client = Redis.from_url(
                self._settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            logger.info("redis_client_created", host=self._settings.redis_host)
        return self._client

    async def ping(self) -> bool:
        """Return True if Redis responds to PING."""
        try:
            return bool(await self.client.ping())
        except Exception as exc:  # noqa: BLE001 - health check must not raise
            logger.warning("redis_ping_failed", error=str(exc))
            return False

    async def close(self) -> None:
        """Close the connection pool on shutdown."""
        if self._client is not None:
            await self._client.aclose()
            logger.info("redis_client_closed")
