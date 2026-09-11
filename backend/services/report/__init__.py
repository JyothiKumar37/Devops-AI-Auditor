"""Multi-format audit report generation.

Builds a single, stable, machine-readable report model from a completed scan's
deterministic findings and the AI reasoning report, then renders it to JSON,
HTML, or PDF. The JSON model is the source of truth; HTML and PDF are views of
the very same model, so all three formats are always consistent.
"""

from services.report.service import ReportFormat, ReportService

__all__ = ["ReportFormat", "ReportService"]
