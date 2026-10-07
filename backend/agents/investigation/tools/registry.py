"""Tool registry: the single catalogue of tools the agent may call."""

from __future__ import annotations

from agents.investigation.tools.base import (
    InvestigationTool,
    ToolContext,
    ToolError,
    ToolPermission,
    ToolResult,
)


class ToolRegistry:
    """Holds the available tools and dispatches validated calls by name."""

    def __init__(self, tools: list[InvestigationTool] | None = None) -> None:
        self._tools: dict[str, InvestigationTool] = {}
        for tool in tools or []:
            self.register(tool)

    def register(self, tool: InvestigationTool) -> None:
        if not tool.name:
            raise ValueError("Tool must define a non-empty name.")
        if tool.name in self._tools:
            raise ValueError(f"Tool '{tool.name}' is already registered.")
        self._tools[tool.name] = tool

    def get(self, name: str) -> InvestigationTool:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolError(f"Unknown tool '{name}'.", code="not_found")
        return tool

    def names(self) -> list[str]:
        return sorted(self._tools)

    def available(self, permissions: frozenset[ToolPermission]) -> list[InvestigationTool]:
        """Tools callable with the given permission set (for LLM tool listing)."""
        return [t for t in self._tools.values() if t.permission in permissions]

    def specs(self, permissions: frozenset[ToolPermission]) -> list[dict]:
        return [t.spec() for t in self.available(permissions)]

    async def call(
        self, name: str, ctx: ToolContext, raw_args: dict | None
    ) -> ToolResult:
        """Look up and invoke a tool by name (raises ToolError on any problem)."""
        return await self.get(name).invoke(ctx, raw_args)


def default_registry() -> ToolRegistry:
    """Build the standard read-only investigation tool registry.

    Imported lazily so the registry module stays import-cycle free and tests can
    build a registry with a subset of tools.
    """
    from agents.investigation.tools import analysis_tools, finding_tools, scan_tools

    return ToolRegistry(
        [
            scan_tools.GetScanSummaryTool(),
            scan_tools.GetScanHistoryTool(),
            finding_tools.GetFindingsTool(),
            finding_tools.GetFindingTool(),
            finding_tools.GetRelatedFindingsTool(),
            finding_tools.GetRootCauseGroupsTool(),
            analysis_tools.GetPostureTool(),
            analysis_tools.GetRiskSummaryTool(),
            analysis_tools.GetScanDiffTool(),
            analysis_tools.GetFileTool(),
            analysis_tools.SearchRepositoryTool(),
        ]
    )
