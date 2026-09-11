"""Security middleware: API-key authentication and request rate limiting.

Both middlewares are deliberately lightweight and dependency-free so they work
identically in tests and in production. They emit the same JSON error envelope
used elsewhere in the API.
"""

from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from core.config import Settings
from core.logging import get_logger

logger = get_logger(__name__)


def _error(status_code: int, code: str, message: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message, "details": {}}},
        headers=headers,
    )


def _client_ip(request: Request, trust_forwarded_for: bool) -> str:
    if trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # First hop is the originating client.
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Require a valid `X-API-Key` on API routes when a key is configured.

    Open (no enforcement) when no key is set. Health checks, docs and CORS
    preflight requests are always exempt so liveness probes and browsers work.
    """

    def __init__(self, app: object, settings: Settings) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._api_key = settings.api_key
        self._api_prefix = settings.api_v1_prefix.rstrip("/")
        self._health_prefix = f"{self._api_prefix}/health"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if self._api_key and self._requires_auth(request):
            provided = request.headers.get("x-api-key", "")
            if not hmac.compare_digest(provided, self._api_key):
                logger.warning("auth_rejected", path=request.url.path)
                return _error(401, "unauthorized", "A valid API key is required.")
        return await call_next(request)

    def _requires_auth(self, request: Request) -> bool:
        if request.method == "OPTIONS":  # CORS preflight
            return False
        path = request.url.path
        if not path.startswith(self._api_prefix):
            return False  # docs, openapi, root, static
        # Liveness/readiness probes stay open; everything else needs a key.
        return not path.startswith(self._health_prefix)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-process sliding-window rate limiter keyed by client IP.

    A general budget applies to all API routes; uploads get a separate, stricter
    budget because they are the most expensive operation. State is per-process
    and bounded by pruning expired timestamps.
    """

    def __init__(self, app: object, settings: Settings) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._enabled = settings.rate_limit_enabled
        self._window = max(1, settings.rate_limit_window_seconds)
        self._general = max(1, settings.rate_limit_requests)
        self._upload = max(1, settings.rate_limit_upload_requests)
        self._api_prefix = settings.api_v1_prefix.rstrip("/")
        self._upload_path = f"{self._api_prefix}/scans/upload"
        self._trust_forwarded_for = settings.trust_forwarded_for
        # bucket key -> deque[timestamps]
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if not self._enabled or request.method == "OPTIONS":
            return await call_next(request)
        path = request.url.path
        if not path.startswith(self._api_prefix):
            return await call_next(request)

        ip = _client_ip(request, self._trust_forwarded_for)
        is_upload = path == self._upload_path and request.method == "POST"
        limit = self._upload if is_upload else self._general
        bucket = f"{'upload' if is_upload else 'general'}:{ip}"

        now = time.monotonic()
        window_start = now - self._window
        hits = self._hits[bucket]
        while hits and hits[0] < window_start:
            hits.popleft()

        if len(hits) >= limit:
            retry_after = max(1, int(self._window - (now - hits[0])))
            logger.warning("rate_limited", path=path, ip=ip, bucket=bucket)
            return _error(
                429,
                "rate_limited",
                "Rate limit exceeded. Please retry later.",
                headers={"Retry-After": str(retry_after)},
            )

        hits.append(now)
        return await call_next(request)
