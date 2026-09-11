"""Report service: load a scan's data and render an export in the chosen format.

Ties together the deterministic findings, the AI reasoning report, and the
report builder, then renders JSON, HTML, or PDF. Returns the rendered bytes
together with the media type and a suggested download filename.
"""

from __future__ import annotations

import re
import uuid
from enum import Enum

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.reasoning import ReasoningService
from core.config import Settings
from core.exceptions import NotFoundError
from models.finding import Finding
from models.scan import RepositoryFile, Scan
from services.report.builder import build_report_model
from services.report.html_report import render_html
from services.report.json_report import render_json
from services.report.model import ReportModel
from services.report.pdf_report import render_pdf


class ReportFormat(str, Enum):
    """Supported export formats."""

    JSON = "json"
    HTML = "html"
    PDF = "pdf"


_MEDIA_TYPE = {
    ReportFormat.JSON: "application/json",
    ReportFormat.HTML: "text/html; charset=utf-8",
    ReportFormat.PDF: "application/pdf",
}
_EXTENSION = {ReportFormat.JSON: "json", ReportFormat.HTML: "html", ReportFormat.PDF: "pdf"}


def _slugify(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")
    return slug or "repository"


class ReportService:
    """Builds and renders multi-format audit reports for a scan."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    async def build_model(self, scan_id: uuid.UUID) -> ReportModel:
        """Load the scan's data and assemble the stable report model."""
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")

        repo_files = (
            await self._session.scalars(
                select(RepositoryFile).where(RepositoryFile.scan_id == scan_id)
            )
        ).all()
        path_by_id = {rf.id: rf.path for rf in repo_files}
        files = [{"file_type": rf.file_type, "size": rf.size} for rf in repo_files]

        findings_rows = list(
            (
                await self._session.scalars(
                    select(Finding).where(Finding.scan_id == scan_id)
                )
            ).all()
        )

        # The reasoning report supplies understanding, readiness and cross-file
        # groups (deterministic when no LLM is configured).
        audit_report = await ReasoningService(
            session=self._session, settings=self._settings
        ).generate_report(scan_id)

        return build_report_model(scan, findings_rows, path_by_id, files, audit_report)

    async def render(
        self, scan_id: uuid.UUID, fmt: ReportFormat
    ) -> tuple[bytes, str, str]:
        """Return (content_bytes, media_type, filename) for the requested format."""
        model = await self.build_model(scan_id)
        if fmt is ReportFormat.JSON:
            content = render_json(model)
        elif fmt is ReportFormat.HTML:
            content = render_html(model).encode("utf-8")
        else:
            content = render_pdf(model)

        filename = f"audit-report-{_slugify(model.repository.name)}.{_EXTENSION[fmt]}"
        return content, _MEDIA_TYPE[fmt], filename
