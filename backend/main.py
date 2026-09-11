"""Application entrypoint and FastAPI app factory.

Wires configuration, structured logging, downstream clients (PostgreSQL, Redis),
the versioned API router, CORS and consistent error handling. Shared singletons
are created during the lifespan and stored on `app.state`.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError, version

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.middleware import APIKeyMiddleware, RateLimitMiddleware
from api.v1.router import api_router
from core.config import Environment, Settings, get_settings
from core.database import Database
from core.exceptions import register_exception_handlers
from core.logging import configure_logging, get_logger
from core.redis import RedisClient
from models.schemas import ServiceInfo
from services.health_service import HealthService


def _app_version() -> str:
    try:
        return version("devops-ai-auditor-backend")
    except PackageNotFoundError:
        return "0.1.0"


def _validate_security_config(settings: Settings) -> None:
    """Fail fast / warn on insecure production configuration."""
    logger = get_logger(__name__)
    if settings.environment is Environment.PRODUCTION:
        if settings.cors_allow_wildcard:
            raise RuntimeError(
                "CORS is set to allow any origin ('*') in production. Configure "
                "explicit CORS_ORIGINS instead."
            )
        if not settings.auth_enabled:
            logger.warning(
                "auth_disabled_in_production",
                detail="No API_KEY is set; the API is unauthenticated.",
            )


def _configure_cors(app: FastAPI, settings: Settings) -> None:
    """Attach CORS with safe credential handling.

    Browsers forbid credentialed requests against a wildcard origin, and pairing
    `allow_credentials=True` with `*` is a well-known misconfiguration. When a
    wildcard origin is configured we therefore disable credentials.
    """
    allow_wildcard = settings.cors_allow_wildcard
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if allow_wildcard else settings.cors_origins_list,
        allow_credentials=not allow_wildcard,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    """Manage startup and shutdown of shared resources."""
    settings: Settings = app.state.settings
    logger = get_logger(__name__)

    app.state.database = Database(settings)
    app.state.redis = RedisClient(settings)
    app.state.health_service = HealthService(
        settings=settings,
        database=app.state.database,
        redis=app.state.redis,
    )

    # Ensure the schema exists (dev/test convenience; production uses migrations).
    # Resilient: a temporarily unreachable database must not block startup.
    await app.state.database.create_all()

    logger.info(
        "application_startup",
        environment=settings.environment.value,
        version=_app_version(),
    )

    try:
        yield
    finally:
        await app.state.database.dispose()
        await app.state.redis.close()
        logger.info("application_shutdown")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Construct and configure the FastAPI application."""
    settings = settings or get_settings()
    configure_logging(settings)

    app = FastAPI(
        title=settings.project_name,
        version=_app_version(),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = settings

    _validate_security_config(settings)

    # Middleware order matters: the LAST added runs OUTERMOST. CORS must be
    # outermost so preflight requests are handled before auth/rate limiting.
    app.add_middleware(APIKeyMiddleware, settings=settings)
    app.add_middleware(RateLimitMiddleware, settings=settings)
    _configure_cors(app, settings)

    register_exception_handlers(app)
    app.include_router(api_router, prefix=settings.api_v1_prefix)

    @app.get("/", response_model=ServiceInfo, tags=["meta"], summary="Service metadata")
    async def root() -> ServiceInfo:
        return ServiceInfo(
            name=settings.project_name,
            version=_app_version(),
            environment=settings.environment.value,
            docs_url="/docs",
        )

    return app


app = create_app()
