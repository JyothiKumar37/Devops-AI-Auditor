"""Aggregates all version 1 endpoint routers under a single router."""

from __future__ import annotations

from fastapi import APIRouter

from api.v1.endpoints import ai, health, scans, settings, stats

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(scans.router)
api_router.include_router(ai.router)
api_router.include_router(settings.router)
api_router.include_router(stats.router)
