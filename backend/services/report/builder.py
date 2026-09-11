"""Deterministic assembly of the report model.

Takes a scan's metadata, its deterministic findings, and the AI reasoning report
and composes them into a single :class:`ReportModel`. Nothing here is random or
LLM-generated: the executive summary and remediation plan are derived by fixed
rules from the underlying data, so the same scan always yields the same report.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from models.enums import Severity
from models.finding import Finding
from models.scan import Scan
from services.report.model import (
    REPORT_SCHEMA_VERSION,
    CategoryScore,
    CrossFileRisk,
    DomainSection,
    ReadinessSection,
    RemediationStep,
    ReportFinding,
    ReportModel,
    RepositoryInfo,
    SeverityBucket,
)

# Severity display order (most severe first) and labels.
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

# Domain (stack/topic) views. Each is a filtered lens over the same findings; a
# finding can legitimately appear in more than one (e.g. a security-category
# Docker rule shows under both "Security" and "Docker").
_DomainPredicate = Callable[["ReportFinding"], bool]


def _scanner_is(*needles: str) -> _DomainPredicate:
    return lambda f: any(n in f.scanner for n in needles)


_DOMAINS: list[tuple[str, str, _DomainPredicate]] = [
    ("security", "Security Findings", lambda f: f.category == "security"),
    ("docker", "Docker Findings", _scanner_is("docker", "compose", "hadolint")),
    ("kubernetes", "Kubernetes Findings", _scanner_is("kubernetes")),
    ("terraform", "Terraform Findings", _scanner_is("terraform")),
    ("cicd", "CI/CD Findings", _scanner_is("github-actions", "gitlab-ci", "jenkins")),
    (
        "secrets",
        "Secret Findings",
        lambda f: f.scanner == "secret-scanner" or f.category == "secrets",
    ),
]

_CATEGORY_LABEL = {
    "security": "Security",
    "reliability": "Reliability",
    "infrastructure": "Infrastructure",
    "kubernetes": "Kubernetes",
    "containers": "Containers",
    "cicd": "CI/CD",
    "ci_cd": "CI/CD",
    "observability": "Observability",
    "maintainability": "Maintainability",
    "supply_chain": "Supply Chain",
    "secrets": "Secrets",
    "efficiency": "Efficiency",
    "best_practice": "Best Practice",
    "configuration": "Configuration",
}


def _severity_rank(severity: str) -> int:
    try:
        return Severity(severity).rank
    except ValueError:
        return 0


def _label_category(value: str) -> str:
    return _CATEGORY_LABEL.get(value, value.replace("_", " ").replace("-", " ").title())


def _rating(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 60:
        return "Fair"
    if score >= 40:
        return "Poor"
    return "Critical"


def _to_report_finding(finding: Finding, path_by_id: dict[uuid.UUID, str]) -> ReportFinding:
    return ReportFinding(
        id=str(finding.id),
        rule_id=str(finding.rule_id),
        scanner=str(finding.scanner),
        category=str(finding.category),
        severity=str(finding.severity),
        confidence=str(finding.confidence),
        title=finding.title,
        description=finding.description or "",
        file=path_by_id.get(finding.file_id) if finding.file_id else None,
        line=finding.line_number,
        evidence=finding.evidence,
        recommendation=finding.recommendation or "",
    )


def _sort_findings(findings: Iterable[ReportFinding]) -> list[ReportFinding]:
    return sorted(
        findings,
        key=lambda f: (
            -_severity_rank(f.severity),
            f.file or "",
            f.line or 0,
            f.rule_id,
        ),
    )


def _severity_buckets(findings: list[ReportFinding]) -> list[SeverityBucket]:
    buckets: list[SeverityBucket] = []
    for sev in _SEVERITY_ORDER:
        items = [f for f in findings if f.severity == sev]
        buckets.append(
            SeverityBucket(
                severity=sev,
                label=_SEVERITY_LABEL[sev],
                count=len(items),
                findings=items,
            )
        )
    return buckets


def _domain_sections(findings: list[ReportFinding]) -> list[DomainSection]:
    sections: list[DomainSection] = []
    for key, label, predicate in _DOMAINS:
        items = [f for f in findings if predicate(f)]
        sections.append(
            DomainSection(key=key, label=label, count=len(items), findings=items)
        )
    return sections


def _remediation_plan(findings: list[ReportFinding]) -> list[RemediationStep]:
    """Group findings by rule and order the fixes by severity then prevalence."""
    grouped: dict[str, dict[str, Any]] = {}
    for f in findings:
        if not f.recommendation:
            continue
        entry = grouped.setdefault(
            f.rule_id,
            {
                "action": f.recommendation,
                "severity": f.severity,
                "files": [],
                "count": 0,
            },
        )
        entry["count"] += 1
        if _severity_rank(f.severity) > _severity_rank(entry["severity"]):
            entry["severity"] = f.severity
        if f.file and f.file not in entry["files"]:
            entry["files"].append(f.file)

    ordered = sorted(
        grouped.items(),
        key=lambda kv: (-_severity_rank(kv[1]["severity"]), -kv[1]["count"], kv[0]),
    )
    plan: list[RemediationStep] = []
    for priority, (rule_id, entry) in enumerate(ordered, start=1):
        plan.append(
            RemediationStep(
                priority=priority,
                severity=entry["severity"],
                action=entry["action"],
                affected_rule_ids=[rule_id],
                affected_files=sorted(entry["files"]),
                finding_count=entry["count"],
            )
        )
    return plan


def _readiness_section(readiness: dict[str, Any]) -> ReadinessSection:
    score = int(readiness.get("score", 0))
    category_scores = [
        CategoryScore(
            category=str(cs.get("category", "")),
            label=_label_category(str(cs.get("category", ""))),
            score=int(cs.get("score", 0)),
            weight=float(cs.get("weight", 0.0)),
            applicable=bool(cs.get("applicable", True)),
            findings=int(cs.get("findings", 0)),
            explanation=str(cs.get("explanation", "")),
        )
        for cs in readiness.get("category_scores", [])
    ]
    return ReadinessSection(
        score=score,
        ready=bool(readiness.get("ready", False)),
        rating=_rating(score),
        summary=str(readiness.get("summary", "")),
        confidence=str(readiness.get("confidence", "medium")),
        category_scores=category_scores,
        blockers=list(readiness.get("blockers", [])),
        top_risks=list(readiness.get("top_risks", [])),
        next_actions=list(readiness.get("next_actions", [])),
        explanation=str(readiness.get("explanation", "")),
    )


def _cross_file_risks(groups: list[dict[str, Any]]) -> list[CrossFileRisk]:
    risks: list[CrossFileRisk] = []
    for g in groups:
        risks.append(
            CrossFileRisk(
                root_cause=str(g.get("root_cause", "")),
                category=str(g.get("category", "")),
                severity=str(g.get("severity", "")),
                confidence=str(g.get("confidence", "")),
                affected_files=list(g.get("affected_files", [])),
                evidence=list(g.get("evidence", [])),
                impact=str(g.get("impact", "")),
                recommendation=str(g.get("recommendation", "")),
            )
        )
    return risks


def _plural(count: int, singular: str) -> str:
    return f"{count} {singular}" + ("" if count == 1 else "s")


def _executive_summary(
    repo: RepositoryInfo,
    readiness: ReadinessSection,
    severity_summary: dict[str, int],
    total_findings: int,
) -> str:
    """A concise, decision-oriented summary written for a DevOps manager."""
    crit = severity_summary.get("critical", 0)
    high = severity_summary.get("high", 0)
    medium = severity_summary.get("medium", 0)
    low = severity_summary.get("low", 0)

    techs = ", ".join(repo.technologies) if repo.technologies else "infrastructure-as-code"
    lines: list[str] = []
    lines.append(
        f"This report summarizes an automated DevOps and security audit of "
        f"\"{repo.name}\", covering {_plural(repo.total_files, 'file')} across {techs}."
    )

    readiness_verb = "is ready" if readiness.ready else "is not yet ready"
    lines.append(
        f"The repository scored {readiness.score}/100 for production readiness "
        f"(rated {readiness.rating}) and {readiness_verb} for production deployment."
    )

    if total_findings == 0:
        lines.append("No issues were detected by the deterministic scanners.")
    else:
        lines.append(
            f"The audit identified {_plural(total_findings, 'finding')}: "
            f"{crit} critical, {high} high, {medium} medium, and {low} low severity."
        )

    if readiness.blockers:
        top = "; ".join(readiness.blockers[:3])
        lines.append(f"Production blockers that must be resolved first: {top}.")

    if not readiness.ready and (crit or high):
        lines.append(
            "We recommend remediating the critical and high-severity issues detailed "
            "below before releasing to production."
        )
    elif readiness.ready:
        lines.append(
            "No production blockers were found; remaining items can be addressed as part "
            "of routine hardening."
        )

    return " ".join(lines)


def build_report_model(
    scan: Scan,
    findings_rows: list[Finding],
    path_by_id: dict[uuid.UUID, str],
    files: list[dict[str, Any]],
    audit_report: dict[str, Any],
) -> ReportModel:
    """Compose the full, stable report model from a scan's data."""
    report_findings = _sort_findings(
        _to_report_finding(f, path_by_id) for f in findings_rows
    )

    file_type_counts: dict[str, int] = {}
    for f in files:
        ft = str(f.get("file_type", "other"))
        file_type_counts[ft] = file_type_counts.get(ft, 0) + 1

    understanding = audit_report.get("understanding", {}) or {}
    repo = RepositoryInfo(
        name=scan.repository_name,
        scan_id=str(scan.id),
        source_type=str(scan.source_type),
        status=str(scan.status),
        created_at=scan.created_at.isoformat() if scan.created_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        total_files=len(files),
        file_type_counts=dict(sorted(file_type_counts.items())),
        technologies=list(understanding.get("technologies", [])),
        components=list(understanding.get("components", [])),
    )

    readiness = _readiness_section(audit_report.get("production_readiness", {}) or {})

    severity_summary = {
        sev: sum(1 for f in report_findings if f.severity == sev) for sev in _SEVERITY_ORDER
    }
    total_findings = len(report_findings)

    exec_summary = _executive_summary(repo, readiness, severity_summary, total_findings)

    return ReportModel(
        schema_version=REPORT_SCHEMA_VERSION,
        report_id=str(uuid.uuid4()),
        generated_at=datetime.now(UTC).isoformat(),
        title=f"DevOps Audit Report — {scan.repository_name}",
        repository=repo,
        executive_summary=exec_summary,
        llm_used=bool(audit_report.get("llm_used", False)),
        production_readiness=readiness,
        total_findings=total_findings,
        reviewed_false_positives=int(audit_report.get("reviewed_false_positives", 0)),
        severity_summary=severity_summary,
        issues_by_severity=_severity_buckets(report_findings),
        findings_by_domain=_domain_sections(report_findings),
        cross_file_risks=_cross_file_risks(audit_report.get("finding_groups", []) or []),
        remediation_plan=_remediation_plan(report_findings),
        recommendations=list(audit_report.get("recommendations", []) or []),
        detailed_findings=report_findings,
    )
