"""LangGraph orchestration for a repository audit.

The graph defines three foundational stages:

    initialize -> plan -> finalize

Each stage currently performs only bookkeeping. Concrete work (file discovery,
dispatching scanners, aggregating and scoring findings) is layered onto this
skeleton in later stages without changing the orchestration contract.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from agents.state import AuditState
from core.logging import get_logger

logger = get_logger(__name__)


def _initialize(state: AuditState) -> AuditState:
    """Prepare the run. Placeholder: no repository work performed yet."""
    logger.info("audit_initialize", job_id=state.get("job_id"))
    return {"findings": [], "completed": False}


def _plan(state: AuditState) -> AuditState:
    """Plan which scanners to run. Placeholder: discovery not implemented yet."""
    logger.info("audit_plan", job_id=state.get("job_id"))
    return {"discovered_files": []}


def _finalize(state: AuditState) -> AuditState:
    """Finalise the run and mark completion."""
    logger.info("audit_finalize", job_id=state.get("job_id"))
    return {"completed": True}


def build_audit_graph():  # type: ignore[no-untyped-def]
    """Build and compile the audit orchestration graph."""
    graph: StateGraph = StateGraph(AuditState)
    graph.add_node("initialize", _initialize)
    graph.add_node("plan", _plan)
    graph.add_node("finalize", _finalize)

    graph.add_edge(START, "initialize")
    graph.add_edge("initialize", "plan")
    graph.add_edge("plan", "finalize")
    graph.add_edge("finalize", END)

    return graph.compile()
