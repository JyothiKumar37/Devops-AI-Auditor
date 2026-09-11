"""Celery application wired to Redis as broker and result backend.

Audits can be long-running, so they are executed off the request path by worker
processes. The foundation ships the worker wiring and a single health task; the
audit-execution task is added alongside the scanners in later stages.
"""

from __future__ import annotations

from celery import Celery

from core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "devops_ai_auditor",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_time_limit=60 * 30,
    worker_hijack_root_logger=False,
)

# Ensure task modules are imported so tasks register on worker startup.
celery_app.autodiscover_tasks(["workers"])
