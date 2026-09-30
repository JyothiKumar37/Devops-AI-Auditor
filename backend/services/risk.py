"""Deterministic, explainable risk prioritisation for findings.

The production-readiness engine (``agents.reasoning.readiness``) scores a whole
repository. This module scores a *single finding* so the UI can rank work by
real-world urgency rather than nominal severity alone.

The score is a deterministic 0-100 number derived only from data already on the
finding (severity, confidence, category, scanner, rule id and text) plus its
recurrence within the scan. It is NEVER asked of an LLM - the AI layer may only
*explain* a score, never set it. The formula anchors on severity but adjusts for:

    exploitability   - secrets / injection / RCE style issues are more urgent
    exposure         - internet-facing / public / world-readable surfaces
    production impact - reliability & availability degradations
    confidence       - low-confidence findings contribute smaller adjustments
    recurrence       - a rule firing repeatedly is a systemic problem
    asset criticality - test/example/vendor paths are less urgent (a multiplier)

so the result is explicitly *not* a restatement of severity. Every adjustment is
bounded per-severity so a low-severity finding can never leapfrog a genuinely
severe one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --- severity anchoring -----------------------------------------------------

# Base points per severity (the anchor - risk still tracks severity closely).
_SEVERITY_BASE = {
    "critical": 60.0, "high": 40.0, "medium": 24.0, "low": 11.0, "info": 4.0,
}
# Upper bound on the additive adjustment a finding of each severity may receive.
# Keeps the ranking monotonic with severity: an info finding can reach at most
# 4+8=12 while a critical can reach 60+40=100, so lower severities cannot
# leapfrog higher ones purely on keyword bonuses.
_MAX_BONUS = {
    "critical": 40.0, "high": 32.0, "medium": 22.0, "low": 12.0, "info": 8.0,
}
# Lower-confidence findings apply smaller adjustments (the base still stands).
_CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.8, "low": 0.55}

# --- priority banding -------------------------------------------------------

PRIORITY_IMMEDIATE = "immediate"
PRIORITY_HIGH = "high"
PRIORITY_NORMAL = "normal"
PRIORITY_LOW = "low"

_PRIORITY_THRESHOLDS = (
    (70, PRIORITY_IMMEDIATE),
    (45, PRIORITY_HIGH),
    (22, PRIORITY_NORMAL),
    (0, PRIORITY_LOW),
)

# --- factor heuristics ------------------------------------------------------

_SECRET_SCANNERS = {"secret-scanner"}
_SECURITY_CATEGORIES = {"security"}
_SUPPLY_CHAIN_CATEGORIES = {"supply_chain"}
_RELIABILITY_CATEGORIES = {"reliability"}

# Exploitability signal words (grounded in the finding's own text).
_EXPLOIT_WORDS = re.compile(
    r"\b("
    r"rce|remote code|injection|sql injection|command injection|deserial|"
    r"privilege escalation|priv-?esc|unauthenticated|auth bypass|traversal|"
    r"ssrf|xxe|exploit|arbitrary (code|command)|hardcoded (secret|password|"
    r"credential|token|key)"
    r")\b",
    re.IGNORECASE,
)
# Internet-exposure / public-surface signal words.
_EXPOSURE_WORDS = re.compile(
    r"\b("
    r"0\.0\.0\.0|0\.0\.0\.0/0|::/0|public|publicly|internet|external|"
    r"loadbalancer|nodeport|ingress|exposed?|world-?readable|world-?writable|"
    r"anonymous|unauthenticated access|open to the (world|internet)|"
    r"allow all|permit all"
    r")\b",
    re.IGNORECASE,
)
# Production-impact / availability signal words.
_IMPACT_WORDS = re.compile(
    r"\b("
    r"liveness|readiness|startup probe|health ?check|resource (limit|request)|"
    r"replicas?|single replica|restart|availability|disruption budget|"
    r"autoscal|out of memory|oom|data loss|no backup"
    r")\b",
    re.IGNORECASE,
)

# Paths that indicate non-production / lower-criticality assets. The scanners
# already downrank severity for these; risk applies a further multiplier so a
# genuine issue in a test fixture is not ranked alongside one in production code.
_LOW_CRITICALITY = re.compile(
    r"(^|/)(tests?|testing|__tests__|spec|specs|examples?|samples?|demos?|"
    r"fixtures?|mocks?|docs?|documentation|vendor|node_modules|\.git)(/|$)",
    re.IGNORECASE,
)
_LOW_CRITICALITY_MULTIPLIER = 0.55


@dataclass(frozen=True, slots=True)
class RiskInput:
    """The minimal, DB-free view of a finding needed to score its risk."""

    rule_id: str
    scanner: str
    category: str
    severity: str
    confidence: str
    title: str = ""
    description: str = ""
    evidence: str | None = None
    file_path: str | None = None
    # How many findings of this rule_id exist in the same scan (>=1).
    recurrence: int = 1


@dataclass(frozen=True, slots=True)
class RiskFactors:
    """The individual, bounded contributions that make up a risk score."""

    severity_base: int
    exploitability: int
    exposure: int
    production_impact: int
    recurrence: int
    confidence_factor: float
    asset_criticality: float


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """The deterministic risk verdict for a single finding."""

    score: int
    priority: str
    factors: RiskFactors
    explanation: str
    signals: list[str] = field(default_factory=list)


def _text_of(inp: RiskInput) -> str:
    return " ".join(
        part for part in (inp.title, inp.description, inp.evidence or "") if part
    )


def _exploitability(inp: RiskInput, text: str) -> int:
    """0-16: how directly the issue can be abused."""
    if inp.scanner in _SECRET_SCANNERS or inp.category == "secrets":
        return 16
    if _EXPLOIT_WORDS.search(text):
        return 13
    if inp.category in _SECURITY_CATEGORIES:
        return 10
    if inp.category in _SUPPLY_CHAIN_CATEGORIES:
        return 7
    return 0


def _exposure(text: str) -> int:
    """0-14: internet-facing / public surface signal."""
    return 14 if _EXPOSURE_WORDS.search(text) else 0


def _production_impact(inp: RiskInput, text: str) -> int:
    """0-10: availability / reliability degradation signal."""
    if inp.category in _RELIABILITY_CATEGORIES:
        return 10
    return 8 if _IMPACT_WORDS.search(text) else 0


def _recurrence_bonus(recurrence: int) -> int:
    """0-6: a rule firing repeatedly points to a systemic problem."""
    if recurrence <= 1:
        return 0
    # 2->2, 3->3, ... capped at 6.
    return min(6, recurrence)


def _asset_criticality(file_path: str | None) -> float:
    if file_path and _LOW_CRITICALITY.search(file_path):
        return _LOW_CRITICALITY_MULTIPLIER
    return 1.0


def _priority_for(score: int) -> str:
    for threshold, label in _PRIORITY_THRESHOLDS:
        if score >= threshold:
            return label
    return PRIORITY_LOW


def assess_risk(inp: RiskInput) -> RiskAssessment:
    """Compute the deterministic risk score (0-100) and priority for a finding."""
    severity = inp.severity if inp.severity in _SEVERITY_BASE else "info"
    confidence = inp.confidence if inp.confidence in _CONFIDENCE_FACTOR else "medium"

    base = _SEVERITY_BASE[severity]
    conf_factor = _CONFIDENCE_FACTOR[confidence]
    text = _text_of(inp)

    exploit = _exploitability(inp, text)
    exposure = _exposure(text)
    impact = _production_impact(inp, text)
    recurrence = _recurrence_bonus(inp.recurrence)

    # Confidence scales the "soft" signal bonuses (not recurrence, which is a
    # hard count), and the whole adjustment is capped per severity.
    raw_bonus = conf_factor * (exploit + exposure + impact) + recurrence
    bonus = min(raw_bonus, _MAX_BONUS[severity])

    criticality = _asset_criticality(inp.file_path)
    score = int(round(max(0.0, min(100.0, (base + bonus) * criticality))))
    priority = _priority_for(score)

    signals: list[str] = []
    if exploit:
        signals.append("exploitability")
    if exposure:
        signals.append("internet-exposure")
    if impact:
        signals.append("production-impact")
    if recurrence:
        signals.append(f"recurs x{inp.recurrence}")
    if criticality < 1.0:
        signals.append("non-production path")

    factors = RiskFactors(
        severity_base=int(round(base)),
        exploitability=exploit,
        exposure=exposure,
        production_impact=impact,
        recurrence=recurrence,
        confidence_factor=conf_factor,
        asset_criticality=criticality,
    )
    explanation = _explain(severity, confidence, factors, score, priority, signals)
    return RiskAssessment(
        score=score, priority=priority, factors=factors, explanation=explanation,
        signals=signals,
    )


def _explain(
    severity: str,
    confidence: str,
    factors: RiskFactors,
    score: int,
    priority: str,
    signals: list[str],
) -> str:
    bits = [
        f"{severity} severity (base {factors.severity_base})",
    ]
    adjustments = []
    if factors.exploitability:
        adjustments.append(f"+{factors.exploitability} exploitability")
    if factors.exposure:
        adjustments.append(f"+{factors.exposure} exposure")
    if factors.production_impact:
        adjustments.append(f"+{factors.production_impact} production impact")
    if factors.recurrence:
        adjustments.append(f"+{factors.recurrence} recurrence")
    if adjustments:
        conf_note = (
            "" if confidence == "high" else f" scaled by {confidence} confidence"
        )
        bits.append("adjustments " + ", ".join(adjustments) + conf_note)
    if factors.asset_criticality < 1.0:
        bits.append(
            f"reduced x{factors.asset_criticality:g} for a non-production path"
        )
    return (
        f"Risk {score}/100 ({priority.replace('_', ' ')} priority): "
        + "; ".join(bits)
        + "."
    )


# --- priority ordering helper ----------------------------------------------

_PRIORITY_RANK = {
    PRIORITY_IMMEDIATE: 3,
    PRIORITY_HIGH: 2,
    PRIORITY_NORMAL: 1,
    PRIORITY_LOW: 0,
}


def priority_rank(priority: str) -> int:
    """Numeric rank for a priority band (higher = more urgent)."""
    return _PRIORITY_RANK.get(priority, 0)
