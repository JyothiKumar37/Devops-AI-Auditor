"""Async PostgreSQL access via SQLAlchemy 2.0.

The engine is created lazily and connections are only established on demand, so
the API process can start and report health even when the database is
temporarily unavailable.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from core.config import Settings
from core.logging import get_logger

logger = get_logger(__name__)


class Database:
    """Owns the async engine and session factory for the application lifecycle."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._engine: AsyncEngine | None = None
        self._sessionmaker: async_sessionmaker[AsyncSession] | None = None

    @property
    def engine(self) -> AsyncEngine:
        if self._engine is None:
            self._engine = create_async_engine(
                self._settings.database_url,
                echo=False,
                pool_pre_ping=True,
                future=True,
            )
            self._sessionmaker = async_sessionmaker(
                bind=self._engine,
                expire_on_commit=False,
                autoflush=False,
            )
            logger.info("database_engine_created", host=self._settings.postgres_host)
        return self._engine

    @property
    def sessionmaker(self) -> async_sessionmaker[AsyncSession]:
        if self._sessionmaker is None:
            # Accessing engine initialises the sessionmaker too.
            _ = self.engine
        assert self._sessionmaker is not None
        return self._sessionmaker

    async def ping(self) -> bool:
        """Return True if a trivial query succeeds against the database."""
        try:
            async with self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception as exc:  # noqa: BLE001 - health check must not raise
            logger.warning("database_ping_failed", error=str(exc))
            return False

    async def create_all(self) -> bool:
        """Create tables for all registered models if they do not exist.

        Convenience for development and tests. Production deployments should use
        managed migrations. Returns True on success, False if the database is
        unreachable (startup must not crash when the DB is temporarily down).
        """
        # Import models so they register on the metadata before create_all.
        from models import scan as _scan  # noqa: F401
        from models.base import Base

        try:
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("database_schema_ready")
            return True
        except Exception as exc:  # noqa: BLE001 - startup must be resilient
            logger.warning("database_schema_init_failed", error=str(exc))
            return False

    async def dispose(self) -> None:
        """Dispose of the connection pool on shutdown."""
        if self._engine is not None:
            await self._engine.dispose()
            logger.info("database_engine_disposed")


async def get_session(db: Database) -> AsyncGenerator[AsyncSession, None]:
    """Yield a transactional session. Intended for use as a FastAPI dependency."""
    async with db.sessionmaker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
