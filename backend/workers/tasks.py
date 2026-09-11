"""Celery task definitions.

Only a health/ping task is defined in the foundation stage. The audit-execution
task that drives the LangGraph orchestrator is added in a later stage.
"""

from __future__ import annotations

from core.logging import get_logger
from workers.celery_app import celery_app

logger = get_logger(__name__)


@celery_app.task(name="workers.ping")
def ping() -> str:
    """Trivial task used to verify the worker and broker are wired correctly."""
    logger.info("worker_ping")
    return "pong"
