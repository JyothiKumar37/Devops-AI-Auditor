"""Agent orchestration built on LangGraph.

Defines the *shape* of the audit pipeline as a graph of stages. Stage bodies are
placeholders in the foundation - they establish the orchestration contract
without performing any real scanning yet.

LangGraph is imported lazily inside `build_audit_graph` so that importing this
package (e.g. for type hints or the state definition) does not require the
LangGraph runtime to be installed.
"""

from agents.state import AuditState

__all__ = ["AuditState", "build_audit_graph"]


def build_audit_graph():  # type: ignore[no-untyped-def]
    """Lazily construct and return the compiled audit graph.

    Imported on demand to keep the heavy LangGraph dependency out of the API
    startup path.
    """
    from agents.orchestrator import build_audit_graph as _build

    return _build()
