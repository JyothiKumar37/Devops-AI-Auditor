"""Standalone HTML rendering of the report model.

Produces a single, self-contained HTML document (inline CSS, no external assets)
suitable for viewing in a browser or printing to PDF from the browser. All
user-derived content is HTML-escaped to prevent injection from finding text,
file paths, or evidence.
"""

from __future__ import annotations

from html import escape

from services.report.model import (
    DomainSection,
    ReportFinding,
    ReportModel,
    SeverityBucket,
)

_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#0284c7",
    "info": "#64748b",
}


def _e(value: object) -> str:
    return escape("" if value is None else str(value))


def _sev_chip(severity: str) -> str:
    color = _SEVERITY_COLOR.get(severity, "#64748b")
    return (
        f'<span class="chip" style="background:{color}1a;color:{color};'
        f'border:1px solid {color}55">{_e(severity.upper())}</span>'
    )


def _location(finding: ReportFinding) -> str:
    if not finding.file:
        return "—"
    loc = _e(finding.file)
    if finding.line:
        loc += f":{finding.line}"
    return f"<code>{loc}</code>"


def _finding_card(finding: ReportFinding) -> str:
    parts = [
        '<div class="finding">',
        '<div class="finding-head">',
        _sev_chip(finding.severity),
        f'<span class="rule">{_e(finding.rule_id)}</span>',
        f'<span class="scanner">{_e(finding.scanner)}</span>',
        f'<span class="ftitle">{_e(finding.title)}</span>',
        "</div>",
        f'<div class="loc">Location: {_location(finding)}</div>',
    ]
    if finding.description:
        parts.append(f'<p class="desc">{_e(finding.description)}</p>')
    if finding.evidence:
        parts.append(f'<pre class="evidence">{_e(finding.evidence)}</pre>')
    if finding.recommendation:
        parts.append(
            f'<p class="rec"><strong>Recommendation:</strong> {_e(finding.recommendation)}</p>'
        )
    parts.append("</div>")
    return "".join(parts)


def _severity_section(bucket: SeverityBucket) -> str:
    color = _SEVERITY_COLOR.get(bucket.severity, "#64748b")
    body = (
        "".join(_finding_card(f) for f in bucket.findings)
        if bucket.findings
        else '<p class="empty">No findings at this severity.</p>'
    )
    return (
        f'<section class="block"><h3 style="border-color:{color}">'
        f"{_e(bucket.label)} Issues "
        f'<span class="count">{bucket.count}</span></h3>{body}</section>'
    )


def _domain_section(section: DomainSection) -> str:
    body = (
        "".join(_finding_card(f) for f in section.findings)
        if section.findings
        else '<p class="empty">No findings in this area.</p>'
    )
    return (
        f'<section class="block"><h3>{_e(section.label)} '
        f'<span class="count">{section.count}</span></h3>{body}</section>'
    )


def _readiness_bars(model: ReportModel) -> str:
    rows = []
    for cs in model.production_readiness.category_scores:
        if not cs.applicable:
            continue
        color = "#16a34a" if cs.score >= 75 else "#d97706" if cs.score >= 50 else "#dc2626"
        rows.append(
            f'<div class="bar-row"><span class="bar-label">{_e(cs.label)}</span>'
            f'<span class="bar-track"><span class="bar-fill" '
            f'style="width:{cs.score}%;background:{color}"></span></span>'
            f'<span class="bar-val">{cs.score}</span></div>'
        )
    return "".join(rows)


def _list_block(title: str, items: list[str]) -> str:
    if not items:
        return ""
    lis = "".join(f"<li>{_e(item)}</li>" for item in items)
    return f'<div class="listcard"><h4>{_e(title)}</h4><ul>{lis}</ul></div>'


def _repo_table(model: ReportModel) -> str:
    r = model.repository
    file_types = ", ".join(f"{_e(k)}: {v}" for k, v in r.file_type_counts.items()) or "—"
    rows = [
        ("Repository", _e(r.name)),
        ("Scan ID", f"<code>{_e(r.scan_id)}</code>"),
        ("Source", _e(r.source_type)),
        ("Status", _e(r.status)),
        ("Completed", _e(r.completed_at or "—")),
        ("Files analyzed", str(r.total_files)),
        ("File types", file_types),
        ("Technologies", _e(", ".join(r.technologies)) or "—"),
        ("Components", _e(", ".join(r.components)) or "—"),
    ]
    body = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows)
    return f'<table class="kv">{body}</table>'


def _remediation_table(model: ReportModel) -> str:
    if not model.remediation_plan:
        return '<p class="empty">No remediation actions required.</p>'
    rows = []
    for step in model.remediation_plan:
        files = ", ".join(step.affected_files) if step.affected_files else "—"
        rows.append(
            f"<tr><td>{step.priority}</td><td>{_sev_chip(step.severity)}</td>"
            f"<td>{_e(step.action)}</td>"
            f"<td><code>{_e(', '.join(step.affected_rule_ids))}</code></td>"
            f"<td>{step.finding_count}</td><td><code>{_e(files)}</code></td></tr>"
        )
    return (
        '<table class="plan"><thead><tr><th>#</th><th>Severity</th><th>Action</th>'
        "<th>Rule</th><th>Findings</th><th>Files</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _cross_file_section(model: ReportModel) -> str:
    if not model.cross_file_risks:
        return '<p class="empty">No cross-file correlations were identified.</p>'
    cards = []
    for risk in model.cross_file_risks:
        evidence = "".join(f"<li>{_e(ev)}</li>" for ev in risk.evidence)
        files = ", ".join(risk.affected_files) if risk.affected_files else "—"
        cards.append(
            f'<div class="finding"><div class="finding-head">{_sev_chip(risk.severity)}'
            f'<span class="ftitle">{_e(risk.root_cause)}</span></div>'
            f'<div class="loc">Affected files: <code>{_e(files)}</code></div>'
            f'<p class="desc"><strong>Impact:</strong> {_e(risk.impact)}</p>'
            f"{'<ul class=evlist>' + evidence + '</ul>' if evidence else ''}"
            f'<p class="rec"><strong>Recommendation:</strong> {_e(risk.recommendation)}</p></div>'
        )
    return "".join(cards)


def _severity_summary_pills(model: ReportModel) -> str:
    pills = []
    for sev in ("critical", "high", "medium", "low", "info"):
        color = _SEVERITY_COLOR[sev]
        count = model.severity_summary.get(sev, 0)
        pills.append(
            f'<div class="sumpill" style="border-color:{color}55">'
            f'<span class="sumcount" style="color:{color}">{count}</span>'
            f'<span class="sumlabel">{sev.title()}</span></div>'
        )
    return "".join(pills)


_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  color: #0f172a; background: #f1f5f9; line-height: 1.55; }
.page { max-width: 960px; margin: 0 auto; padding: 40px 32px 80px; }
header.report { border-bottom: 3px solid #0f172a; padding-bottom: 16px; margin-bottom: 28px; }
header.report h1 { margin: 0 0 4px; font-size: 26px; }
header.report .meta { color: #64748b; font-size: 13px; }
h2 { font-size: 19px; margin: 34px 0 12px; padding-bottom: 6px; border-bottom: 1px solid #cbd5e1; }
h3 { font-size: 15px; margin: 20px 0 10px; padding-left: 10px; border-left: 4px solid #94a3b8; }
h4 { font-size: 13px; margin: 0 0 6px; text-transform: uppercase; letter-spacing: .04em; color: #475569; }
p { margin: 8px 0; }
code { font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; font-size: 12px;
  background: #e2e8f0; padding: 1px 5px; border-radius: 4px; }
.summary { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 18px 20px;
  font-size: 15px; }
.score-wrap { display: flex; gap: 24px; align-items: center; background: #fff; border: 1px solid #e2e8f0;
  border-radius: 10px; padding: 20px; }
.score-badge { font-size: 44px; font-weight: 800; width: 128px; text-align: center; }
.score-badge small { display:block; font-size: 13px; font-weight: 600; color: #64748b; }
.ready { display:inline-block; padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; }
.ready.yes { background:#dcfce7; color:#166534; } .ready.no { background:#fee2e2; color:#991b1b; }
.bars { flex: 1; min-width: 0; }
.bar-row { display:flex; align-items:center; gap:10px; margin:5px 0; font-size:12px; }
.bar-label { width: 120px; color:#334155; } .bar-val { width: 28px; text-align:right; color:#334155; }
.bar-track { flex:1; height:8px; background:#e2e8f0; border-radius:999px; overflow:hidden; }
.bar-fill { display:block; height:100%; }
.kv { width:100%; border-collapse: collapse; background:#fff; border:1px solid #e2e8f0; border-radius:10px; }
.kv th { text-align:left; width: 180px; color:#475569; font-weight:600; vertical-align:top;
  padding: 8px 14px; border-bottom:1px solid #f1f5f9; font-size: 13px; }
.kv td { padding: 8px 14px; border-bottom:1px solid #f1f5f9; font-size: 13px; }
.summary-pills { display:flex; gap:12px; margin: 6px 0 4px; flex-wrap: wrap; }
.sumpill { background:#fff; border:1px solid; border-radius:10px; padding:10px 16px; text-align:center; min-width:78px; }
.sumcount { display:block; font-size:24px; font-weight:800; } .sumlabel { font-size:12px; color:#64748b; }
.block { margin-top: 8px; }
.count { display:inline-block; background:#e2e8f0; color:#334155; border-radius:999px; font-size:12px;
  padding:0 8px; margin-left:6px; font-weight:600; }
.finding { background:#fff; border:1px solid #e2e8f0; border-radius:8px; padding:12px 14px; margin:8px 0; }
.finding-head { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.chip { font-size:10px; font-weight:700; padding:1px 7px; border-radius:999px; letter-spacing:.03em; }
.rule { font-family: Consolas, monospace; font-size:11px; color:#475569; background:#f1f5f9; padding:1px 6px; border-radius:4px; }
.scanner { font-size:11px; color:#94a3b8; }
.ftitle { font-weight:600; font-size:14px; }
.loc { font-size:12px; color:#64748b; margin-top:4px; }
.desc { font-size:13px; color:#334155; }
.evidence { background:#0f172a; color:#fbbf24; font-size:12px; padding:8px 10px; border-radius:6px;
  overflow-x:auto; white-space:pre-wrap; word-break:break-word; }
.rec { font-size:13px; color:#334155; }
.empty { color:#94a3b8; font-style:italic; font-size:13px; }
table.plan { width:100%; border-collapse:collapse; background:#fff; border:1px solid #e2e8f0; font-size:13px; }
table.plan th, table.plan td { padding:8px 10px; border-bottom:1px solid #f1f5f9; text-align:left; vertical-align:top; }
table.plan thead th { background:#f8fafc; color:#475569; font-size:12px; }
.listcard { background:#fff; border:1px solid #e2e8f0; border-radius:8px; padding:12px 16px; margin:8px 0; }
.listcard ul, .evlist { margin:4px 0 0; padding-left:20px; } .listcard li { font-size:13px; margin:3px 0; }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
@media print { body { background:#fff; } .page { padding: 0; } .finding, .kv, .summary, .score-wrap { break-inside: avoid; } }
"""


def render_html(model: ReportModel) -> str:
    """Render the report model to a single, self-contained HTML document."""
    pr = model.production_readiness
    ready_cls = "yes" if pr.ready else "no"
    ready_txt = "Production Ready" if pr.ready else "Not Production Ready"
    score_color = (
        "#16a34a" if pr.score >= 75 else "#d97706" if pr.score >= 50 else "#dc2626"
    )

    severity_sections = "".join(
        _severity_section(b) for b in model.issues_by_severity if b.severity != "info"
    )
    domain_sections = "".join(_domain_section(s) for s in model.findings_by_domain)
    detailed = (
        "".join(_finding_card(f) for f in model.detailed_findings)
        if model.detailed_findings
        else '<p class="empty">No findings.</p>'
    )
    recommendations = _list_block("Recommendations", model.recommendations)

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(model.title)}</title>
<style>{_CSS}</style></head>
<body><div class="page">
<header class="report">
  <h1>{_e(model.title)}</h1>
  <div class="meta">Generated {_e(model.generated_at)} · Schema v{_e(model.schema_version)}
   · Report ID {_e(model.report_id)}</div>
</header>

<h2>Executive Summary</h2>
<div class="summary">{_e(model.executive_summary)}</div>

<h2>Repository Information</h2>
{_repo_table(model)}

<h2>Production Readiness Score</h2>
<div class="score-wrap">
  <div class="score-badge" style="color:{score_color}">{pr.score}<small>/ 100 · {_e(pr.rating)}</small></div>
  <div class="bars">
    <div style="margin-bottom:8px"><span class="ready {ready_cls}">{_e(ready_txt)}</span></div>
    {_readiness_bars(model)}
  </div>
</div>
<div class="grid2">
  {_list_block("Production Blockers", pr.blockers)}
  {_list_block("Top Risks", pr.top_risks)}
</div>
{_list_block("Recommended Next Actions", pr.next_actions)}

<h2>Issues by Severity</h2>
<div class="summary-pills">{_severity_summary_pills(model)}</div>
{severity_sections}

<h2>Findings by Area</h2>
{domain_sections}

<h2>Cross-file Risks</h2>
{_cross_file_section(model)}

<h2>Recommended Remediation Plan</h2>
{_remediation_table(model)}
{recommendations}

<h2>Detailed Findings</h2>
{detailed}

</div></body></html>"""
    return html
