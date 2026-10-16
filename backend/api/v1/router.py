"""Aggregates all version 1 endpoint routers under a single router."""

from __future__ import annotations

from fastapi import APIRouter

from api.v1.endpoints import (
    ai,
    audit,
    cloud,
    containment,
    health,
    incidents,
    integrations,
    investigations,
    notifications,
    policies,
    pull_requests,
    scans,
    security,
    settings,
    stats,
    webhooks,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(scans.router)
api_router.include_router(ai.router)
api_router.include_router(investigations.router)
api_router.include_router(settings.router)
api_router.include_router(stats.router)
api_router.include_router(integrations.router)
api_router.include_router(webhooks.router)
api_router.include_router(pull_requests.router)
api_router.include_router(policies.router)
api_router.include_router(notifications.router)
api_router.include_router(audit.router)
api_router.include_router(cloud.router)
api_router.include_router(security.router)
api_router.include_router(incidents.router)
api_router.include_router(containment.router)
