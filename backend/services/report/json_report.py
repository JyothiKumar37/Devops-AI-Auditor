"""JSON rendering of the report model.

The JSON is the canonical, machine-readable representation: stable key order
(Pydantic preserves field declaration order), a ``schema_version`` for
consumers, and UTF-8 output. Deterministic given the same model.
"""

from __future__ import annotations

import json

from services.report.model import ReportModel


def render_json(model: ReportModel) -> bytes:
    """Serialize the report model to stable, pretty-printed JSON bytes."""
    payload = model.model_dump(mode="json")
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False)
    return text.encode("utf-8")
