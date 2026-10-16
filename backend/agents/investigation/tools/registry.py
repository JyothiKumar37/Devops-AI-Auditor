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
    from agents.investigation.tools import (
        analysis_tools,
        cloud_tools,
        finding_tools,
        scan_tools,
    )

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
            # Phase 4 cloud tools (read-only, account-scoped, secret-redacted).
            cloud_tools.ListCloudAccountsTool(),
            cloud_tools.GetCloudAssetsTool(),
            cloud_tools.GetCloudResourceTool(),
            cloud_tools.GetCloudFindingsTool(),
            cloud_tools.GetCloudPostureTool(),
            cloud_tools.GetNetworkGraphTool(),
            cloud_tools.GetIamAnalysisTool(),
            cloud_tools.GetDriftTool(),
            cloud_tools.GetComplianceStatusTool(),
        ]
    )


def incident_registry() -> ToolRegistry:
    """Registry for incident investigations: incident tools + all cloud/scan tools.

    An incident spans cloud resources, so the Phase 4 cloud tools are included and
    authorized for the incident's cloud account; the incident tools add the
    event/timeline/containment evidence specific to the incident.
    """
    from agents.investigation.tools import incident_tools

    registry = default_registry()
    for tool in (
        incident_tools.GetIncidentTool(),
        incident_tools.SearchSecurityEventsTool(),
        incident_tools.GetSecurityEventTool(),
        incident_tools.GetIncidentTimelineTool(),
        incident_tools.GetRemediationHistoryTool(),
    ):
        registry.register(tool)
    return registry
