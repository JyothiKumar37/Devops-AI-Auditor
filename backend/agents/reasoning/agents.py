"""The reasoning agents.

The specialized agents mirror the architecture's AI Agent System: repository
understanding, security, Kubernetes, container infrastructure, Terraform, CI/CD,
cross-file correlation and false-positive review, followed by prioritization,
the production-readiness engine and report generation.

Each agent runs the configured LLM when available and otherwise falls back to a
deterministic, evidence-grounded computation. In both cases the anti-hallucination
guard applies: an AI finding is only kept if it is backed by a deterministic
finding that exists in the scan state. The AI never invents infrastructure or
unsupported technical claims.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from pydantic import BaseModel

from agents.reasoning.llm import LLMProvider, generate_structured
from agents.reasoning.sanitize import (
    guardrail_system,
    neutralize,
    sanitize_catalogue_entry,
    wrap_untrusted,
)
from agents.reasoning.schemas import (
    AIFinding,
    Correlation,
    FalsePositiveAssessment,
    FindingGroup,
    ProductionReadiness,
    RepositoryUnderstanding,
)
from agents.reasoning.state import ReasoningState
from core.logging import get_logger
from models.enums import Confidence, Severity

logger = get_logger(__name__)

_SECURITY_CATEGORIES = {"security", "secrets", "supply_chain"}
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

_NON_PROD_PATH_MARKERS = (
    "test", "tests", "__tests__", "spec", "specs", "e2e", "example", "examples",
    "fixture", "fixtures", "sample", "samples", "mock", "mocks", "__mocks__",
    "docs", "vendor", "node_modules", ".terraform",
)
_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")

_TECH_BY_FILETYPE = {
    "dockerfile": "Docker", "docker_compose": "Docker Compose", "kubernetes": "Kubernetes",
    "helm_chart": "Helm", "helm_values": "Helm", "helm_template": "Helm",
    "terraform": "Terraform", "github_actions": "GitHub Actions", "gitlab_ci": "GitLab CI",
    "jenkins": "Jenkins", "ansible_playbook": "Ansible", "ansible_role": "Ansible",
}


class _AIFindingList(BaseModel):
    findings: list[AIFinding] = []


class _CorrelationList(BaseModel):
    correlations: list[Correlation] = []


def _dump(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")


def _evidence(finding: dict[str, Any]) -> str:
    return finding.get("evidence") or finding.get("description") or finding.get("title") or "n/a"


def _source(finding: dict[str, Any]) -> str:
    return f"{finding.get('scanner')}:{finding.get('rule_id')}"


# ---------------------------------------------------------------------------
# 1. Repository Understanding Agent
# ---------------------------------------------------------------------------


def repository_understanding(state: ReasoningState, provider: LLMProvider) -> dict[str, Any]:
    files = state.get("files", [])
    findings = state.get("findings", [])

    technologies = sorted(
        {
            _TECH_BY_FILETYPE[f["file_type"]]
            for f in files
            if f.get("file_type") in _TECH_BY_FILETYPE
        }
    )
    components = sorted(
        {(f["path"].split("/")[0] if "/" in f["path"] else ".") for f in files}
    )[:15]
    risk_areas = sorted({f["category"] for f in findings})

    summary = (
        f"Repository contains {len(files)} files. Detected technologies: "
        f"{', '.join(technologies) or 'none identified'}. "
        f"{len(findings)} deterministic findings across {len(risk_areas)} categories."
    )
    understanding = RepositoryUnderstanding(
        summary=summary,
        technologies=technologies,
        components=components,
        risk_areas=risk_areas,
        confidence=Confidence.HIGH if files else Confidence.LOW,
    )
    return {"understanding": _dump(understanding), "llm_used": provider.available}


# ---------------------------------------------------------------------------
# 2-5. Specialized reasoning agents
# ---------------------------------------------------------------------------


def _to_ai_finding(finding: dict[str, Any], reasoning: str) -> AIFinding:
    return AIFinding(
        title=finding["title"],
        category=finding["category"],
        severity=finding["severity"],
        confidence=finding["confidence"],
        file=finding.get("file"),
        line=finding.get("line"),
        evidence=_evidence(finding),
        source=_source(finding),
        reasoning=reasoning,
        recommendation=finding.get("recommendation") or "Review and remediate the issue.",
        source_finding_ids=[finding["id"]],
    )


def _validate_grounded(items: list[AIFinding], allowed_ids: set[str]) -> list[AIFinding]:
    """Anti-hallucination guard: keep only findings grounded in allowed ids."""
    kept: list[AIFinding] = []
    for item in items:
        ids = set(item.source_finding_ids)
        if ids and ids.issubset(allowed_ids) and item.evidence.strip():
            kept.append(item)
    return kept


def _reason_domain(
    provider: LLMProvider,
    domain: str,
    subset: list[dict[str, Any]],
    reasoning_hint: str,
) -> list[dict[str, Any]]:
    if not subset:
        return []
    allowed_ids = {f["id"] for f in subset}
    by_id = {f["id"]: f for f in subset}

    if provider.available:
        # Every field below is derived from the (untrusted) repository. It is
        # neutralised and passed only inside the delimited data block; the
        # hardened system prompt instructs the model to treat it as data.
        catalogue = [
            sanitize_catalogue_entry(
                {
                    "id": f["id"], "scanner": f["scanner"], "rule_id": f["rule_id"],
                    "title": f["title"], "severity": f["severity"], "file": f.get("file"),
                    "line": f.get("line"), "evidence": _evidence(f),
                }
            )
            for f in subset
        ]
        system = guardrail_system(f"the {domain} reasoning agent")
        user = (
            "Analyse the deterministic scanner findings in the untrusted data block "
            "below and explain each real finding and its impact. Return JSON: "
            '{"findings": [AIFinding, ...]}.\n\n'
            + wrap_untrusted(json.dumps(catalogue, indent=2))
        )
        result = generate_structured(provider, system=system, user=user, schema=_AIFindingList)
        if result is not None:
            grounded = _validate_grounded(result.findings, allowed_ids)
            if grounded:
                # Trust ONLY the model's explanatory reasoning (neutralised);
                # every other field is rebuilt from the authoritative
                # deterministic finding so the model cannot poison evidence,
                # source, severity or file even on a grounded id.
                rebuilt = [
                    _to_ai_finding(
                        by_id[item.source_finding_ids[0]],
                        neutralize(item.reasoning) or "Reported by a deterministic scanner.",
                    )
                    for item in grounded
                ]
                return [_dump(f) for f in rebuilt]
            logger.warning("llm_domain_ungrounded", domain=domain)

    # Deterministic fallback.
    return [
        _dump(_to_ai_finding(f, f"{reasoning_hint} (reported by {_source(f)})."))
        for f in subset
    ]


def _security_subset(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [f for f in findings if f["category"] in _SECURITY_CATEGORIES]


def _domain_subset(findings: list[dict[str, Any]], scanners: set[str]) -> list[dict[str, Any]]:
    return [
        f for f in findings
        if f["scanner"] in scanners and f["category"] not in _SECURITY_CATEGORIES
    ]


def security_reasoning(state: ReasoningState, provider: LLMProvider) -> dict[str, Any]:
    subset = _security_subset(state.get("findings", []))
    produced = _reason_domain(
        provider, "security", subset,
        "This is a security exposure that could be exploited",
    )
    return {"domain_findings": state.get("domain_findings", []) + produced}


def kubernetes_reasoning(state: ReasoningState, provider: LLMProvider) -> dict[str, Any]:
    subset = _domain_subset(state.get("findings", []), {"kubernetes-rules"})
    produced = _reason_domain(
        provider, "kubernetes", subset,
        "This affects Kubernetes workload reliability or configuration correctness",
    )
    return {"domain_findings": state.get("domain_findings", []) + produced}


def infrastructure_reasoning(state: ReasoningState, provider: LLMProvider) -> dict[str, Any]:
    # Container infrastructure (Docker images + Compose). Terraform is handled by
    # its own dedicated agent below.
    subset = _domain_subset(state.get("findings", []), {"docker-rules", "compose-rules"})
    produced = _reason_domain(
        provider, "container infrastructure", subset,
        "This affects container image or Docker Compose reliability, efficiency "
        "or configuration",
    )
    return {"domain_findings": state.get("domain_findings", []) + produced}


def terraform_reasoning(state: ReasoningState, provider: LLMProvider) -> dict[str, Any]:
    subset = _domain_subset(state.get("findings", []), {"terraform-rules"})
    produced = _reason_domain(
        provider, "terraform", subset,
        "This affects the security or reliability of the Terraform-defined "
        "cloud infrastructure",
    )
    return {"domain_findings": state.get("domain_findings", []) + produced}


def cicd_reasoning(state: ReasoningState, provider: LLMProvider) -> dict[str, Any]:
    subset = _domain_subset(
        state.get("findings", []),
        {"github-actions-rules", "gitlab-ci-rules", "jenkins-rules", "actionlint"},
    )
    produced = _reason_domain(
        provider, "ci/cd", subset,
        "This affects the safety or reliability of the CI/CD pipeline",
    )
    return {"domain_findings": state.get("domain_findings", []) + produced}


# ---------------------------------------------------------------------------
# 6. Cross-File Correlation Agent
# ---------------------------------------------------------------------------


def cross_file_correlation(state: ReasoningState, provider: LLMProvider) -> dict[str, Any]:
    findings = state.get("findings", [])
    relationships = state.get("relationships", [])
    correlations: list[Correlation] = []

    # 1) Deterministic cross-resource relationship findings.
    for rel in relationships:
        correlations.append(
            Correlation(
                title=rel["title"],
                description=rel.get("description") or rel["title"],
                severity=rel["severity"],
                confidence=Confidence.HIGH,
                involved_files=[rel["file"]] if rel.get("file") else [],
                source_finding_ids=[rel["id"]],
                reasoning="Detected by cross-file relationship analysis across manifests.",
                recommendation=rel.get("recommendation") or "Align the related resources.",
            )
        )

    # 2) The same secret appearing in multiple files.
    by_evidence: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        if f["scanner"] == "secret-scanner" and f.get("evidence"):
            by_evidence[f["evidence"]].append(f)
    for evidence, group in by_evidence.items():
        files = sorted({g["file"] for g in group if g.get("file")})
        if len(files) > 1:
            correlations.append(
                Correlation(
                    title="Same secret referenced in multiple files",
                    description=f"A secret ({evidence}) appears in {len(files)} files.",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    involved_files=files,
                    source_finding_ids=[g["id"] for g in group],
                    reasoning="Identical masked secret evidence was found across files.",
                    recommendation="Rotate the secret and centralise it in a secrets manager.",
                )
            )

    # Root-cause grouping across stacks (reduces duplicate symptoms into issues).
    from agents.reasoning.correlation import correlate

    groups = correlate(findings, state.get("correlation_index", {}))
    return {
        "correlations": [_dump(c) for c in correlations],
        "finding_groups": [_dump(g) for g in groups],
    }


# ---------------------------------------------------------------------------
# 7. False Positive Review Agent
# ---------------------------------------------------------------------------


def false_positive_review(state: ReasoningState, provider: LLMProvider) -> dict[str, Any]:
    assessments: list[FalsePositiveAssessment] = []
    for f in state.get("findings", []):
        path = (f.get("file") or "").lower()
        parts = set(path.replace("\\", "/").split("/"))
        name = path.rsplit("/", 1)[-1]
        is_template = name.endswith(_TEMPLATE_SUFFIXES)
        in_non_prod = bool(parts & set(_NON_PROD_PATH_MARKERS)) or is_template
        low_impact = f["severity"] in {"info", "low"}
        if in_non_prod and low_impact:
            assessments.append(
                FalsePositiveAssessment(
                    finding_id=f["id"],
                    is_false_positive=True,
                    confidence=Confidence.MEDIUM,
                    reasoning="Low-impact finding located in a non-production path "
                    "(tests/examples/docs/vendored code).",
                )
            )
    return {"false_positives": [_dump(a) for a in assessments]}


# ---------------------------------------------------------------------------
# 8. Severity prioritization (workflow step) + Production Readiness Agent
# ---------------------------------------------------------------------------


def prioritize(state: ReasoningState, provider: LLMProvider) -> dict[str, Any]:
    fp_ids = {
        a["finding_id"] for a in state.get("false_positives", []) if a["is_false_positive"]
    }
    kept = [
        af for af in state.get("domain_findings", [])
        if not (set(af.get("source_finding_ids", [])) & fp_ids)
    ]
    kept.sort(
        key=lambda af: (
            Severity(af["severity"]).rank,
            _CONFIDENCE_RANK.get(af["confidence"], 1),
        ),
        reverse=True,
    )
    return {"prioritized": kept}


def production_readiness(state: ReasoningState, provider: LLMProvider) -> dict[str, Any]:
    from agents.reasoning.readiness import assess

    # Score the authoritative deterministic findings, excluding confirmed FPs.
    fp_ids = {
        a["finding_id"] for a in state.get("false_positives", []) if a["is_false_positive"]
    }
    findings = [f for f in state.get("findings", []) if f["id"] not in fp_ids]
    report = assess(findings, state.get("files", []))
    return {"readiness": _dump(report)}


# ---------------------------------------------------------------------------
# 9. Report Generation Agent
# ---------------------------------------------------------------------------


def report_generation(state: ReasoningState, provider: LLMProvider) -> dict[str, Any]:
    from agents.reasoning.schemas import AuditReport

    findings = state.get("findings", [])
    prioritized = state.get("prioritized", [])
    correlations = state.get("correlations", [])
    fp = state.get("false_positives", [])

    # Authoritative severity counts come from ALL deterministic findings.
    severity_counts = {s.value: 0 for s in Severity}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    readiness = ProductionReadiness.model_validate(state["readiness"])
    understanding = RepositoryUnderstanding.model_validate(state["understanding"])

    key_findings = [AIFinding.model_validate(af) for af in prioritized[:20]]
    recommendations: list[str] = []
    for af in key_findings:
        if af.recommendation not in recommendations:
            recommendations.append(af.recommendation)
    recommendations = recommendations[:10]

    summary = (
        f"{len(findings)} findings detected; {len(prioritized)} prioritized after "
        f"reviewing {len([a for a in fp if a['is_false_positive']])} likely false positives. "
        f"Production readiness score: {readiness.score}/100."
    )

    report = AuditReport(
        scan_id=state.get("scan_id", ""),
        summary=summary,
        llm_used=bool(state.get("llm_used", False)),
        understanding=understanding,
        severity_counts=severity_counts,
        total_findings=len(findings),
        reviewed_false_positives=len([a for a in fp if a["is_false_positive"]]),
        key_findings=key_findings,
        correlations=[Correlation.model_validate(c) for c in correlations],
        finding_groups=[FindingGroup.model_validate(g) for g in state.get("finding_groups", [])],
        production_readiness=readiness,
        recommendations=recommendations,
    )
    return {"report": _dump(report)}
