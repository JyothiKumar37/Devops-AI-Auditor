"""Phase 3 agentic investigation layer.

An evidence-grounded, tool-based AI investigation engine that sits ALONGSIDE the
deterministic scanner/policy engine (which remains the authoritative source of
truth). The AI never mutates data, never executes code, and reaches application
data only through a controlled, read-only tool layer with argument validation,
result bounding, and secret redaction.
"""

from __future__ import annotations
