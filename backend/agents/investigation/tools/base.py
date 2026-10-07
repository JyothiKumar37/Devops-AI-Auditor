"""Tool framework: permissions, context, result, and the tool base class.

Design goals (see Phase 3 safety rules):
- The LLM can only act through these tools (no SQL/shell/code execution).
- Every call is authorized (permission class + scan scope), argument-validated
  (Pydantic), size-bounded, and logged.
- Results are structured and already secret-redacted by the tool implementation.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar

from pydantic import BaseModel, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.logging import get_logger

logger = get_logger(__name__)


class ToolPermission(str, Enum):
    """Capability classes a tool can require.

    Investigations are granted READ only. REMEDIATION tools (plan/patch/rescan)
    exist for later milestones and always require explicit human approval - they
    are never granted to the autonomous investigation loop.
    """

    READ = "read"
    REMEDIATION = "remediation"


class ToolError(Exception):
    """Raised when a tool call is rejected or fails.

    ``code`` lets the engine/tests distinguish rejection reasons without string
    matching: ``unauthorized`` | ``invalid_arguments`` | ``not_found`` | ``error``.
    """

    def __init__(self, message: str, *, code: str = "error") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class ToolArgs(BaseModel):
    """Base class for tool argument schemas. Rejects unknown fields."""

    model_config = {"extra": "forbid"}


@dataclass(slots=True)
class ToolContext:
    """Everything a tool needs to run within one investigation's authorization.

    - ``session``/``settings``: wired like every other service.
    - ``authorized_scan_ids``: the scans this investigation may read. ``None``
      means "no scan restriction" (repository-level investigation). A tool that
      accepts a ``scan_id`` must have it within this set, otherwise the call is
      rejected as unauthorized - this is what stops the agent wandering outside
      the scope it was opened for.
    - ``granted_permissions``: capability classes the agent currently holds
      (READ for investigations).
    - ``repository_name``: optional repo scope for repository-level tools.
    """

    session: AsyncSession
    settings: Settings
    authorized_scan_ids: frozenset[uuid.UUID] | None = None
    granted_permissions: frozenset[ToolPermission] = frozenset({ToolPermission.READ})
    repository_name: str | None = None

    def authorizes_scan(self, scan_id: uuid.UUID) -> bool:
        return self.authorized_scan_ids is None or scan_id in self.authorized_scan_ids


@dataclass(slots=True)
class ToolResult:
    """Structured, bounded output returned to the engine (and ultimately the LLM).

    ``data`` is JSON-serializable. ``truncated``/``total_available``/``returned``
    make result bounding explicit so the model knows when it is seeing a subset.
    """

    data: Any
    returned: int = 0
    total_available: int | None = None
    truncated: bool = False
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        meta: dict[str, Any] = {"returned": self.returned, "truncated": self.truncated}
        if self.total_available is not None:
            meta["total_available"] = self.total_available
        if self.note:
            meta["note"] = self.note
        return {"data": self.data, "meta": meta}


class InvestigationTool(ABC):
    """Base class for a controlled investigation tool.

    Subclasses set ``name``/``description``/``args_schema``/``permission`` and
    implement :meth:`_run`. Call :meth:`invoke` (not ``_run``) so authorization,
    validation, bounding and logging are enforced uniformly.
    """

    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    args_schema: ClassVar[type[ToolArgs]] = ToolArgs
    permission: ClassVar[ToolPermission] = ToolPermission.READ

    async def invoke(self, ctx: ToolContext, raw_args: dict[str, Any] | None) -> ToolResult:
        """Validate + authorize + run a tool call. Raises :class:`ToolError`."""
        if self.permission not in ctx.granted_permissions:
            raise ToolError(
                f"Tool '{self.name}' requires the '{self.permission.value}' permission.",
                code="unauthorized",
            )
        try:
            args = self.args_schema.model_validate(raw_args or {})
        except ValidationError as exc:
            raise ToolError(
                f"Invalid arguments for '{self.name}': {exc.errors()[:3]}",
                code="invalid_arguments",
            ) from exc

        # Scope enforcement: any tool argument named scan_id must be authorized.
        scan_id = getattr(args, "scan_id", None)
        if isinstance(scan_id, uuid.UUID) and not ctx.authorizes_scan(scan_id):
            raise ToolError(
                f"Scan {scan_id} is outside this investigation's authorized scope.",
                code="unauthorized",
            )

        started = time.monotonic()
        try:
            result = await self._run(ctx, args)
        except ToolError:
            raise
        except Exception as exc:  # noqa: BLE001 - surface as a controlled tool error
            logger.warning("tool_failed", tool=self.name, error=str(exc))
            raise ToolError(f"Tool '{self.name}' failed: {exc}", code="error") from exc

        logger.info(
            "tool_invoked",
            tool=self.name,
            returned=result.returned,
            truncated=result.truncated,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return result

    @abstractmethod
    async def _run(self, ctx: ToolContext, args: ToolArgs) -> ToolResult:
        """Execute the validated tool call. Implemented by subclasses."""

    @classmethod
    def spec(cls) -> dict[str, Any]:
        """A compact, LLM-facing description of the tool and its arguments."""
        return {
            "name": cls.name,
            "description": cls.description,
            "permission": cls.permission.value,
            "arguments": cls.args_schema.model_json_schema().get("properties", {}),
        }


# Shared bounding constants so no single tool can return an unbounded blob.
MAX_LIMIT = 50
DEFAULT_LIMIT = 20
MAX_FILE_BYTES = 8000
MAX_FILE_LINES = 400
MAX_SEARCH_MATCHES = 50


def clamp_limit(limit: int, *, default: int = DEFAULT_LIMIT, maximum: int = MAX_LIMIT) -> int:
    """Clamp a requested result limit into ``[1, maximum]``."""
    if limit <= 0:
        return default
    return min(limit, maximum)


# Re-exported for tools to annotate without importing field directly.
__all__ = [
    "DEFAULT_LIMIT",
    "InvestigationTool",
    "MAX_FILE_BYTES",
    "MAX_FILE_LINES",
    "MAX_LIMIT",
    "MAX_SEARCH_MATCHES",
    "ToolArgs",
    "ToolContext",
    "ToolError",
    "ToolPermission",
    "ToolResult",
    "clamp_limit",
    "field",
]
