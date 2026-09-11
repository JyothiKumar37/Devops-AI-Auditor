"""Deterministic cross-file correlation engine.

Combines related deterministic findings (and the cross-stack entity index) into
root-cause `FindingGroup`s, reducing several symptoms to one issue with a full
evidence trail. Every group is grounded in real member findings / extracted
entities - nothing is invented, and groups are only emitted when their required
evidence is present.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from agents.reasoning.schemas import FindingGroup
from models.enums import Confidence, FindingCategory, Severity


def _max_severity(findings: list[dict[str, Any]]) -> Severity:
    best = Severity.INFO
    for f in findings:
        sev = Severity(f.get("severity", "info"))
        if sev.rank > best.rank:
            best = sev
    return best


def _files(findings: list[dict[str, Any]]) -> list[str]:
    return sorted({f["file"] for f in findings if f.get("file")})


def _evidence(findings: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for f in findings:
        piece = f.get("evidence") or f.get("title") or ""
        label = f"{f.get('file') or '?'}:{f.get('line') or '?'} [{f.get('rule_id', '?')}] {piece}"
        out.append(label)
    return out


def correlate(findings: list[dict[str, Any]], index: dict[str, Any]) -> list[FindingGroup]:
    """Return root-cause finding groups derived from findings + entity index."""
    index = index or {}
    groups: list[FindingGroup] = []
    by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        by_rule[f.get("rule_id", "")].append(f)

    groups += _public_database_exposure(by_rule, index)
    groups += _cicd_namespace_inconsistency(index)
    groups += _mutable_image_with_ci_build(by_rule, index)
    groups += _database_multi_issue(by_rule)
    groups += _duplicate_secrets(findings)
    groups += _kubernetes_wiring(by_rule)
    return groups


def _public_database_exposure(
    by_rule: dict[str, list[dict[str, Any]]], index: dict[str, Any]
) -> list[FindingGroup]:
    public_rds = by_rule.get("TF004", [])
    open_db = by_rule.get("TF003", [])
    if not (public_rds and open_db):
        return []

    consumers = [w for w in index.get("k8s_workloads", []) if w.get("db_hosts")]
    members = public_rds + open_db
    affected = set(_files(members))
    evidence = _evidence(public_rds) + _evidence(open_db)
    impact = (
        "The database is reachable directly from the internet and its port is open "
        "to 0.0.0.0/0, allowing credential brute-forcing and direct data exfiltration."
    )
    if consumers:
        for w in consumers:
            affected.add(w["file"])
            evidence.append(
                f"{w['file']}: workload '{w['name']}' connects to a database "
                f"(namespace {w['namespace']})."
            )
        impact += (
            " A Kubernetes workload depends on this database, so a compromise directly "
            "affects the application's data."
        )

    return [
        FindingGroup(
            root_cause="Publicly accessible database exposed to the internet",
            category=FindingCategory.SECURITY,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            affected_files=sorted(affected),
            evidence=evidence,
            impact=impact,
            recommendation=(
                "Set publicly_accessible = false, restrict the security group to the "
                "application's private subnets/security groups, and place the database "
                "in private subnets."
            ),
            member_finding_ids=[f["id"] for f in members],
        )
    ]


def _cicd_namespace_inconsistency(index: dict[str, Any]) -> list[FindingGroup]:
    cicd = index.get("cicd", {}) or {}
    workloads = index.get("k8s_workloads", [])
    if not (cicd.get("has_kubectl") and cicd.get("deploy_namespaces") and workloads):
        return []

    defined = set(index.get("k8s_namespaces", [])) | {"default"}
    missing = [ns for ns in cicd["deploy_namespaces"] if ns not in defined]
    if not missing:
        return []

    affected = sorted(set(cicd.get("files", [])) | {w["file"] for w in workloads})
    return [
        FindingGroup(
            root_cause="CI/CD deploys to a namespace not defined by the Kubernetes manifests",
            category=FindingCategory.CONFIGURATION,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            affected_files=affected,
            evidence=[
                f"CI/CD targets namespace(s): {', '.join(missing)}",
                f"Manifests define namespaces: {', '.join(sorted(defined)) or 'default'}",
            ],
            impact=(
                "Deploying to a namespace the manifests do not define can lead to failed "
                "or split-brain deployments and resources landing in the wrong place."
            ),
            recommendation=(
                "Align the CI/CD deploy namespace with the manifests, or add a Namespace "
                "manifest for the target."
            ),
            member_finding_ids=[],
        )
    ]


def _mutable_image_with_ci_build(
    by_rule: dict[str, list[dict[str, Any]]], index: dict[str, Any]
) -> list[FindingGroup]:
    cicd = index.get("cicd", {}) or {}
    latest = by_rule.get("K8S030", [])
    if not (cicd.get("has_image_build") and latest):
        return []

    affected = sorted(set(cicd.get("files", [])) | set(_files(latest)))
    return [
        FindingGroup(
            root_cause="CI/CD builds images while Kubernetes deploys a mutable ':latest' tag",
            category=FindingCategory.SUPPLY_CHAIN,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            affected_files=affected,
            evidence=["CI/CD pipeline builds container images", *_evidence(latest)],
            impact=(
                "Because the deployment references ':latest', the running image is not "
                "reproducible and rollbacks are unreliable despite the pipeline producing "
                "specific builds."
            ),
            recommendation=(
                "Deploy the immutable image tag/digest produced by the pipeline instead "
                "of ':latest'."
            ),
            member_finding_ids=[f["id"] for f in latest],
        )
    ]


_DB_ISSUE_RULES = {"TF006", "TF010", "TF011", "TF012"}


def _database_multi_issue(
    by_rule: dict[str, list[dict[str, Any]]],
) -> list[FindingGroup]:
    by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rule in _DB_ISSUE_RULES:
        for f in by_rule.get(rule, []):
            if f.get("file"):
                by_file[f["file"]].append(f)

    groups: list[FindingGroup] = []
    for file, members in by_file.items():
        if len(members) < 2:
            continue
        groups.append(
            FindingGroup(
                root_cause=f"Database configuration in {file} has multiple reliability/"
                "encryption issues",
                category=FindingCategory.RELIABILITY,
                severity=_max_severity(members),
                confidence=Confidence.HIGH,
                affected_files=[file],
                evidence=_evidence(members),
                impact=(
                    "Several database hardening controls (encryption, backups, deletion "
                    "protection, multi-AZ) are missing together, compounding data-loss risk."
                ),
                recommendation="Address the grouped database settings together as one change.",
                member_finding_ids=[f["id"] for f in members],
            )
        )
    return groups


def _duplicate_secrets(findings: list[dict[str, Any]]) -> list[FindingGroup]:
    by_evidence: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        if f.get("scanner") == "secret-scanner" and f.get("evidence"):
            by_evidence[f["evidence"]].append(f)

    groups: list[FindingGroup] = []
    for evidence, members in by_evidence.items():
        files = _files(members)
        if len(files) < 2:
            continue
        groups.append(
            FindingGroup(
                root_cause="The same secret is committed in multiple files",
                category=FindingCategory.SECRETS,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                affected_files=files,
                evidence=[f"Masked value {evidence} appears in: {', '.join(files)}"],
                impact=(
                    "A single leaked credential is duplicated across the repository, "
                    "widening exposure and making rotation error-prone."
                ),
                recommendation=(
                    "Rotate the secret and reference it from a single secrets manager entry."
                ),
                member_finding_ids=[f["id"] for f in members],
            )
        )
    return groups


_WIRING_RULES = {"K8S070", "K8S071", "K8S072", "K8S073", "K8S074"}


def _kubernetes_wiring(by_rule: dict[str, list[dict[str, Any]]]) -> list[FindingGroup]:
    members: list[dict[str, Any]] = []
    for rule in _WIRING_RULES:
        members.extend(by_rule.get(rule, []))
    if len(members) < 2:
        return []
    return [
        FindingGroup(
            root_cause="Kubernetes service/ingress wiring is inconsistent across manifests",
            category=FindingCategory.RELIABILITY,
            severity=_max_severity(members),
            confidence=Confidence.HIGH,
            affected_files=_files(members),
            evidence=_evidence(members),
            impact=(
                "Selector/port/backend mismatches across Deployment, Service and Ingress "
                "mean traffic will not reach the intended pods."
            ),
            recommendation=(
                "Align pod labels, Service selectors/targetPort and Ingress backends so the "
                "request path is consistent end to end."
            ),
            member_finding_ids=[f["id"] for f in members],
        )
    ]
