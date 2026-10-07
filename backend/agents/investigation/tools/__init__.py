"""Controlled, read-only tool layer for the AI investigation engine.

The LLM never touches the database, the shell, or repository code directly. It
may only call the registered tools here. Every tool validates its arguments,
enforces the investigation's authorization scope, bounds its result size, and
redacts secrets before returning structured data.
"""

from __future__ import annotations

from agents.investigation.tools.base import (
    InvestigationTool,
    ToolContext,
    ToolError,
    ToolPermission,
    ToolResult,
)
from agents.investigation.tools.registry import ToolRegistry, default_registry

__all__ = [
    "InvestigationTool",
    "ToolContext",
    "ToolError",
    "ToolPermission",
    "ToolRegistry",
    "ToolResult",
    "default_registry",
]
