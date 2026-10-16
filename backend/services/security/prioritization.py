"""Deterministic incident risk prioritization (pure, explainable, no I/O).

The priority score (0-100) is computed only from deterministic signals and always
comes with a per-factor rationale so it can be explained and reproduced. AI never
feeds into this score - the engine stays the authority; AI may *explain* the
score but cannot change it.

Double-counting guard: the same underlying issue (identified by an event's dedup
fingerprint and its (resource, event_type)) is only counted once, so an incident
with five deliveries of the same alert is not scored higher than one with a single
delivery of it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from models.enums import SecurityEventCategory, Severity
from models.incident import IncidentResource
from models.security import SecurityEvent

# Factor weights (sum of maxima == 100). Severity dominates; the rest refine it.
_W_SEVERITY = 40
_W_EXPOSURE = 20
_W_PRIVILEGE = 12
_W_EXPLOITABILITY = 12
_W_BLAST_RADIUS = 8
_W_VERIFIED = 8

_SEVERITY_POINTS = {
    Severity.CRITICAL.value: 40,
    Severity.HIGH.value: 30,
    Severity.MEDIUM.value: 18,
    Severity.LOW.value: 8,
    Severity.INFO.value: 2,
}

# Categories that indicate an active/exploitable threat rather than a latent misconfig.
_EXPLOIT_CATEGORIES = {
    SecurityEventCategory.THREAT.value,
    SecurityEventCategory.RUNTIME.value,
}
_PRIVILEGE_CATEGORIES = {SecurityEventCategory.IDENTITY.value}
_EXPOSURE_CATEGORIES = {SecurityEventCategory.EXPOSURE.value}


def _now() -> datetime:
    return datetime.now(UTC)


def _sev_rank(value: str) -> int:
    try:
        return Severity(value).rank
    except ValueError:
        return 0


@dataclass(slots=True)
class PriorityResult:
    score: int
    severity: str
    rationale: dict[str, Any]


def compute_priority(
    events: list[SecurityEvent],
    resources: list[IncidentResource],
    *,
    compensating_controls: int = 0,
) -> PriorityResult:
    """Compute an incident's deterministic priority (0-100) + rationale.

    ``compensating_controls`` (e.g. an accepted compliance exception covering the
    resource) subtracts from the score, never below zero.
    """
    if not events:
        return PriorityResult(score=0, severity=Severity.INFO.value, rationale={"factors": []})

    # Dedup underlying issues so repeated deliveries don't inflate the score.
    unique: dict[str, SecurityEvent] = {}
    for ev in events:
        key = ev.fingerprint or f"{ev.resource_id}:{ev.event_type}"
        if key not in unique or _sev_rank(ev.severity) > _sev_rank(unique[key].severity):
            unique[key] = ev
    distinct = list(unique.values())

    factors: list[dict[str, Any]] = []

    # 1) Severity: the single most severe distinct issue.
    top_sev = max((e.severity for e in distinct), key=_sev_rank)
    sev_points = _SEVERITY_POINTS.get(top_sev, 0)
    factors.append({
        "factor": "severity", "points": sev_points, "max": _W_SEVERITY,
        "detail": f"Most severe distinct signal is {top_sev}.",
    })

    # 2) Public exposure: any affected resource publicly reachable, or an exposure event.
    public = any(r.exposure == "public" for r in resources)
    exposure_event = any(e.category in _EXPOSURE_CATEGORIES for e in distinct)
    exp_points = _W_EXPOSURE if public else (_W_EXPOSURE // 2 if exposure_event else 0)
    factors.append({
        "factor": "exposure", "points": exp_points, "max": _W_EXPOSURE,
        "detail": (
            "A resource is publicly reachable." if public
            else "An exposure signal is present." if exposure_event
            else "No public exposure observed."
        ),
    })

    # 3) Privilege: identity/IAM involvement raises impact.
    privilege = any(e.category in _PRIVILEGE_CATEGORIES or e.principal for e in distinct)
    priv_points = _W_PRIVILEGE if privilege else 0
    factors.append({
        "factor": "privilege", "points": priv_points, "max": _W_PRIVILEGE,
        "detail": "An IAM principal/identity is involved." if privilege else "No identity signal.",
    })

    # 4) Exploitability: active threat/runtime signal (e.g. GuardDuty, Falco).
    exploit = any(e.category in _EXPLOIT_CATEGORIES for e in distinct)
    exploit_points = _W_EXPLOITABILITY if exploit else 0
    exploit_detail = (
        "An active threat/runtime signal is present." if exploit else "No active-threat signal."
    )
    factors.append({
        "factor": "exploitability", "points": exploit_points, "max": _W_EXPLOITABILITY,
        "detail": exploit_detail,
    })

    # 5) Blast radius: number of distinct affected resources (bounded).
    resource_count = len({r.resource_id for r in resources})
    radius_points = min(_W_BLAST_RADIUS, max(0, resource_count - 1) * 2)
    factors.append({
        "factor": "blast_radius", "points": radius_points, "max": _W_BLAST_RADIUS,
        "detail": f"{resource_count} affected resource(s).",
    })

    # 6) Verification: at least one independently-verified signal increases confidence.
    verified = any(e.verified for e in distinct)
    verified_points = _W_VERIFIED if verified else 0
    factors.append({
        "factor": "verified", "points": verified_points, "max": _W_VERIFIED,
        "detail": (
            "At least one signal is independently verified by our scanners."
            if verified else "All signals are externally reported (unverified)."
        ),
    })

    subtotal = sum(f["points"] for f in factors)

    # Compensating controls reduce the score (explicitly recorded).
    control_reduction = min(subtotal, compensating_controls * 10)
    if control_reduction:
        factors.append({
            "factor": "compensating_controls", "points": -control_reduction, "max": 0,
            "detail": f"{compensating_controls} compensating control(s) applied.",
        })

    score = max(0, min(100, subtotal - control_reduction))
    return PriorityResult(score=score, severity=top_sev, rationale={
        "factors": factors,
        "distinct_issues": len(distinct),
        "total_signals": len(events),
        "computed_at": _now().isoformat(),
        "method": "deterministic",
    })
