"""PDF rendering of the report model via ReportLab (Platypus).

Produces a professional, multi-page PDF from the same report model used for JSON
and HTML. Rendering is deterministic and needs no external binaries. All
user-derived text is XML-escaped before being placed into flowable paragraphs.
"""

from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    ListFlowable,
    ListItem,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from services.report.model import DomainSection, ReportFinding, ReportModel, SeverityBucket

_SEVERITY_HEX = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#0284c7",
    "info": "#64748b",
}
_INK = colors.HexColor("#0f172a")
_MUTED = colors.HexColor("#64748b")
_PANEL = colors.HexColor("#f1f5f9")


def _e(value: object) -> str:
    return escape("" if value is None else str(value))


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = base["BodyText"]
    body.fontSize = 9.5
    body.leading = 14
    styles = {
        "title": ParagraphStyle(
            "rTitle", parent=base["Title"], fontSize=20, leading=24,
            textColor=_INK, spaceAfter=2,
        ),
        "meta": ParagraphStyle("rMeta", parent=body, fontSize=8, textColor=_MUTED),
        "h2": ParagraphStyle(
            "rH2", parent=base["Heading2"], fontSize=14, textColor=_INK,
            spaceBefore=14, spaceAfter=4,
        ),
        "h3": ParagraphStyle(
            "rH3", parent=base["Heading3"], fontSize=11, textColor=_INK,
            spaceBefore=8, spaceAfter=2,
        ),
        "body": body,
        "small": ParagraphStyle("rSmall", parent=body, fontSize=8, textColor=_MUTED),
        "code": ParagraphStyle(
            "rCode", parent=body, fontName="Courier", fontSize=8,
            textColor=colors.HexColor("#b45309"),
            backColor=colors.HexColor("#fff7ed"), borderPadding=4, leading=11,
        ),
        "rec": ParagraphStyle(
            "rRec", parent=body, fontSize=9, textColor=colors.HexColor("#334155")
        ),
    }
    return styles


def _sev_tag(severity: str) -> str:
    hexc = _SEVERITY_HEX.get(severity, "#64748b")
    return f'<font color="{hexc}"><b>{_e(severity.upper())}</b></font>'


def _location(finding: ReportFinding) -> str:
    if not finding.file:
        return "—"
    loc = _e(finding.file)
    if finding.line:
        loc += f":{finding.line}"
    return loc


def _finding_full(finding: ReportFinding, st: dict[str, ParagraphStyle]) -> list:
    flow: list = [
        Paragraph(
            f"{_sev_tag(finding.severity)} &nbsp;<b>{_e(finding.title)}</b> "
            f'<font color="#64748b" size="8">'
            f"[{_e(finding.rule_id)} · {_e(finding.scanner)}]</font>",
            st["body"],
        ),
        Paragraph(
            f'Location: <font face="Courier">{_location(finding)}</font>', st["small"]
        ),
    ]
    if finding.description:
        flow.append(Paragraph(_e(finding.description), st["body"]))
    if finding.evidence:
        flow.append(Paragraph(_e(finding.evidence), st["code"]))
    if finding.recommendation:
        flow.append(
            Paragraph(f"<b>Recommendation:</b> {_e(finding.recommendation)}", st["rec"])
        )
    flow.append(Spacer(1, 6))
    return flow


def _finding_compact(finding: ReportFinding, st: dict[str, ParagraphStyle]) -> Paragraph:
    return Paragraph(
        f"{_sev_tag(finding.severity)} &nbsp;<b>{_e(finding.title)}</b> "
        f'<font color="#64748b" size="8">[{_e(finding.rule_id)}]</font><br/>'
        f'<font color="#64748b" size="8">{_location(finding)}</font>',
        st["body"],
    )


def _kv_table(rows: list[tuple[str, str]], st: dict[str, ParagraphStyle], width: float) -> Table:
    data = [
        [Paragraph(f"<b>{_e(k)}</b>", st["small"]), Paragraph(v, st["small"])]
        for k, v in rows
    ]
    table = Table(data, colWidths=[45 * mm, width - 45 * mm])
    table.setStyle(
        TableStyle(
            [
                ("LINEBELOW", (0, 0), (-1, -1), 0.4, _PANEL),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    return table


def _bullets(items: list[str], st: dict[str, ParagraphStyle]) -> ListFlowable:
    return ListFlowable(
        [ListItem(Paragraph(_e(i), st["body"]), leftIndent=10) for i in items],
        bulletType="bullet",
        start="•",
    )


def _severity_block(bucket: SeverityBucket, st: dict[str, ParagraphStyle]) -> list:
    flow: list = [Paragraph(f"{_e(bucket.label)} Issues ({bucket.count})", st["h3"])]
    if not bucket.findings:
        flow.append(Paragraph("No findings at this severity.", st["small"]))
    else:
        for f in bucket.findings:
            flow.append(_finding_compact(f, st))
            flow.append(Spacer(1, 3))
    return flow


def _domain_block(section: DomainSection, st: dict[str, ParagraphStyle]) -> list:
    flow: list = [Paragraph(f"{_e(section.label)} ({section.count})", st["h3"])]
    if not section.findings:
        flow.append(Paragraph("No findings in this area.", st["small"]))
    else:
        for f in section.findings:
            flow.append(_finding_compact(f, st))
            flow.append(Spacer(1, 3))
    return flow


def _remediation_table(model: ReportModel, st: dict[str, ParagraphStyle], width: float) -> Table:
    header = [
        Paragraph("<b>#</b>", st["small"]),
        Paragraph("<b>Sev</b>", st["small"]),
        Paragraph("<b>Action</b>", st["small"]),
        Paragraph("<b>Rule</b>", st["small"]),
        Paragraph("<b>N</b>", st["small"]),
    ]
    data = [header]
    for step in model.remediation_plan:
        data.append(
            [
                Paragraph(str(step.priority), st["small"]),
                Paragraph(_sev_tag(step.severity), st["small"]),
                Paragraph(_e(step.action), st["small"]),
                Paragraph(
                    f'<font face="Courier">'
                    f'{_e(", ".join(step.affected_rule_ids))}</font>',
                    st["small"],
                ),
                Paragraph(str(step.finding_count), st["small"]),
            ]
        )
    table = Table(
        data,
        colWidths=[8 * mm, 16 * mm, width - 66 * mm, 30 * mm, 12 * mm],
        repeatRows=1,
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                ("LINEBELOW", (0, 0), (-1, -1), 0.4, _PANEL),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def render_pdf(model: ReportModel) -> bytes:
    """Render the report model to PDF bytes."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=model.title,
    )
    width = doc.width
    st = _styles()
    pr = model.production_readiness
    story: list = []

    # Header
    story.append(Paragraph(_e(model.title), st["title"]))
    story.append(
        Paragraph(
            f"Generated {_e(model.generated_at)} · Schema v{_e(model.schema_version)} "
            f"· Report ID {_e(model.report_id)}",
            st["meta"],
        )
    )
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=1.5, color=_INK, spaceAfter=8))

    # Executive summary
    story.append(Paragraph("Executive Summary", st["h2"]))
    story.append(Paragraph(_e(model.executive_summary), st["body"]))

    # Repository information
    r = model.repository
    file_types = ", ".join(f"{k}: {v}" for k, v in r.file_type_counts.items()) or "—"
    story.append(Paragraph("Repository Information", st["h2"]))
    story.append(
        _kv_table(
            [
                ("Repository", _e(r.name)),
                ("Scan ID", _e(r.scan_id)),
                ("Source", _e(r.source_type)),
                ("Status", _e(r.status)),
                ("Completed", _e(r.completed_at or "—")),
                ("Files analyzed", str(r.total_files)),
                ("File types", _e(file_types)),
                ("Technologies", _e(", ".join(r.technologies)) or "—"),
                ("Components", _e(", ".join(r.components)) or "—"),
            ],
            st,
            width,
        )
    )

    # Production readiness
    story.append(Paragraph("Production Readiness Score", st["h2"]))
    score_hex = "#16a34a" if pr.score >= 75 else "#d97706" if pr.score >= 50 else "#dc2626"
    ready_txt = "Production Ready" if pr.ready else "Not Production Ready"
    story.append(
        Paragraph(
            f'<font color="{score_hex}" size="30"><b>{pr.score}</b></font>'
            f'<font color="#64748b" size="11"> / 100 · {_e(pr.rating)} · {_e(ready_txt)}</font>',
            st["body"],
        )
    )
    if pr.summary:
        story.append(Paragraph(_e(pr.summary), st["small"]))
    applicable = [cs for cs in pr.category_scores if cs.applicable]
    if applicable:
        cat_rows = [
            [Paragraph("<b>Category</b>", st["small"]), Paragraph("<b>Score</b>", st["small"])]
        ]
        for cs in applicable:
            cat_rows.append(
                [
                    Paragraph(_e(cs.label), st["small"]),
                    Paragraph(f"{cs.score} / 100", st["small"]),
                ]
            )
        cat_table = Table(cat_rows, colWidths=[width - 30 * mm, 30 * mm])
        cat_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.4, _PANEL),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(Spacer(1, 6))
        story.append(cat_table)
    if pr.blockers:
        story.append(Paragraph("Production Blockers", st["h3"]))
        story.append(_bullets(pr.blockers, st))
    if pr.top_risks:
        story.append(Paragraph("Top Risks", st["h3"]))
        story.append(_bullets(pr.top_risks, st))
    if pr.next_actions:
        story.append(Paragraph("Recommended Next Actions", st["h3"]))
        story.append(_bullets(pr.next_actions, st))

    # Issues by severity
    story.append(Paragraph("Issues by Severity", st["h2"]))
    summary_bits = " · ".join(
        f"{_sev_tag(s)} {model.severity_summary.get(s, 0)}"
        for s in ("critical", "high", "medium", "low", "info")
    )
    story.append(Paragraph(summary_bits, st["body"]))
    for bucket in model.issues_by_severity:
        if bucket.severity == "info":
            continue
        for flowable in _severity_block(bucket, st):
            story.append(flowable)

    # Findings by area
    story.append(Paragraph("Findings by Area", st["h2"]))
    for section in model.findings_by_domain:
        for flowable in _domain_block(section, st):
            story.append(flowable)

    # Cross-file risks
    story.append(Paragraph("Cross-file Risks", st["h2"]))
    if not model.cross_file_risks:
        story.append(Paragraph("No cross-file correlations were identified.", st["small"]))
    else:
        for risk in model.cross_file_risks:
            story.append(
                Paragraph(
                    f"{_sev_tag(risk.severity)} &nbsp;<b>{_e(risk.root_cause)}</b>",
                    st["body"],
                )
            )
            files = ", ".join(risk.affected_files) if risk.affected_files else "—"
            story.append(Paragraph(f"Affected files: {_e(files)}", st["small"]))
            story.append(Paragraph(f"<b>Impact:</b> {_e(risk.impact)}", st["body"]))
            if risk.evidence:
                story.append(_bullets(risk.evidence, st))
            story.append(
                Paragraph(f"<b>Recommendation:</b> {_e(risk.recommendation)}", st["rec"])
            )
            story.append(Spacer(1, 6))

    # Remediation plan
    story.append(Paragraph("Recommended Remediation Plan", st["h2"]))
    if model.remediation_plan:
        story.append(_remediation_table(model, st, width))
    else:
        story.append(Paragraph("No remediation actions required.", st["small"]))
    if model.recommendations:
        story.append(Paragraph("Recommendations", st["h3"]))
        story.append(_bullets(model.recommendations, st))

    # Detailed findings
    story.append(Paragraph("Detailed Findings", st["h2"]))
    if not model.detailed_findings:
        story.append(Paragraph("No findings.", st["small"]))
    else:
        for f in model.detailed_findings:
            for flowable in _finding_full(f, st):
                story.append(flowable)

    doc.build(story)
    return buffer.getvalue()
