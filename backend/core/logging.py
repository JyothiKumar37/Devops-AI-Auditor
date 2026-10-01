"""Structured logging configuration built on structlog.

Provides JSON output for production and a readable console renderer for local
development. All application code should obtain a logger via `get_logger`.
"""

from __future__ import annotations

import logging
import sys

import structlog

from core.config import Settings


def configure_logging(settings: Settings) -> None:
    """Configure the standard library logging and structlog pipelines.

    Should be called once during application startup.
    """
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]

    if settings.log_json:
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        # Logs go to stderr; stdout is reserved for program output (e.g. the CLI
        # emits machine-readable JSON/SARIF there, which log lines must not corrupt).
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    # Route stdlib logging (uvicorn, sqlalchemy, etc.) through the same level,
    # also to stderr so it never mixes with program output on stdout.
    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        handlers=[logging.StreamHandler(sys.stderr)],
        force=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger."""
    return structlog.get_logger(name)
