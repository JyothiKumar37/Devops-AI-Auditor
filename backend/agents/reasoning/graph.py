"""LangGraph wiring for the reasoning workflow.

    repository understanding
        -> security / kubernetes / infrastructure / terraform / ci-cd reasoning
        -> cross-file correlation
        -> false-positive review
        -> severity prioritization
        -> production readiness
        -> report generation

The specialized reasoning agents run in sequence so they accumulate into a
single findings list. Nodes are bound to the configured LLM provider.
"""

from __future__ import annotations

from functools import partial

from langgraph.graph import END, START, StateGraph

from agents.reasoning import agents
from agents.reasoning.llm import LLMProvider
from agents.reasoning.state import ReasoningState

_NODES = [
    ("repository_understanding", agents.repository_understanding),
    ("security_reasoning", agents.security_reasoning),
    ("kubernetes_reasoning", agents.kubernetes_reasoning),
    ("infrastructure_reasoning", agents.infrastructure_reasoning),
    ("terraform_reasoning", agents.terraform_reasoning),
    ("cicd_reasoning", agents.cicd_reasoning),
    ("cross_file_correlation", agents.cross_file_correlation),
    ("false_positive_review", agents.false_positive_review),
    ("prioritize", agents.prioritize),
    ("production_readiness", agents.production_readiness),
    ("report_generation", agents.report_generation),
]


def build_reasoning_graph(provider: LLMProvider):  # type: ignore[no-untyped-def]
    """Build and compile the reasoning graph bound to `provider`."""
    graph: StateGraph = StateGraph(ReasoningState)

    for name, func in _NODES:
        graph.add_node(name, partial(func, provider=provider))

    graph.add_edge(START, _NODES[0][0])
    for (current, _), (nxt, _) in zip(_NODES, _NODES[1:], strict=False):
        graph.add_edge(current, nxt)
    graph.add_edge(_NODES[-1][0], END)

    return graph.compile()
