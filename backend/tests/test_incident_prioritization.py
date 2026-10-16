"""M7 tests: deterministic incident risk prioritization (explainable, no double count)."""

from __future__ import annotations

import uuid

from models.cloud import CloudAccount, ComplianceException
from models.incident import IncidentResource
from models.security import SecurityEvent
from services.incident_service import IncidentService
from services.security.prioritization import compute_priority


def _event(**kw) -> SecurityEvent:
    base = dict(
        id=uuid.uuid4(), source_type="guardduty", source_event_id=str(uuid.uuid4()),
        category="threat", event_type="Recon", severity="high", confidence="medium",
        title="event", fingerprint=uuid.uuid4().hex, status="new",
    )
    base.update(kw)
    return SecurityEvent(**base)


def _resource(resource_id="i-1", exposure="private") -> IncidentResource:
    return IncidentResource(
        id=uuid.uuid4(), incident_id=uuid.uuid4(), resource_id=resource_id,
        resource_arn="", service="ec2", region="us-east-1", exposure=exposure,
    )


# ---- pure function -----------------------------------------------------------


def test_critical_public_threat_scores_high() -> None:
    events = [_event(severity="critical", category="threat", verified=True)]
    resources = [_resource(exposure="public")]
    result = compute_priority(events, resources)
    assert result.score >= 70
    assert result.severity == "critical"
    factors = {f["factor"]: f["points"] for f in result.rationale["factors"]}
    assert factors["severity"] == 40
    assert factors["exposure"] == 20
    assert factors["exploitability"] == 12


def test_low_private_misconfig_scores_low() -> None:
    events = [_event(severity="low", category="misconfiguration", verified=False)]
    resources = [_resource(exposure="private")]
    result = compute_priority(events, resources)
    assert result.score < 20


def test_duplicate_signals_not_double_counted() -> None:
    fp = uuid.uuid4().hex
    events = [
        _event(severity="high", fingerprint=fp, resource_id="i-1"),
        _event(severity="high", fingerprint=fp, resource_id="i-1"),  # same underlying issue
    ]
    resources = [_resource()]
    one = compute_priority([events[0]], resources)
    two = compute_priority(events, resources)
    assert one.score == two.score  # dedup by fingerprint
    assert two.rationale["distinct_issues"] == 1
    assert two.rationale["total_signals"] == 2


def test_compensating_controls_reduce_score() -> None:
    events = [_event(severity="critical", category="threat")]
    resources = [_resource(exposure="public")]
    base = compute_priority(events, resources)
    reduced = compute_priority(events, resources, compensating_controls=1)
    assert reduced.score == base.score - 10
    assert any(f["factor"] == "compensating_controls" for f in reduced.rationale["factors"])


# ---- integration via IncidentService ----------------------------------------


async def test_correlation_sets_priority_and_rationale(mem_db) -> None:
    sm, settings = mem_db
    async with sm() as session:
        session.add(_event(account_ref="acct", resource_id="i-1", severity="critical",
                           category="threat", verified=True))
        await session.commit()
        svc = IncidentService(session, settings)
        incidents = await svc.correlate_new_events()
        await session.commit()
        inc = incidents[0]
        assert inc.priority > 0
        assert inc.risk_rationale.get("method") == "deterministic"
        assert "factors" in inc.risk_rationale


async def test_compensating_exception_lowers_incident_priority(mem_db) -> None:
    sm, settings = mem_db
    acct = uuid.uuid4()
    async with sm() as session:
        session.add(CloudAccount(
            id=acct, provider="aws", name="p", account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/RO", regions=["us-east-1"],
            status="connected",
        ))
        session.add(_event(cloud_account_id=acct, account_ref="123456789012",
                           resource_id="i-1", severity="critical", category="threat"))
        await session.commit()
        svc = IncidentService(session, settings)
        incidents = await svc.correlate_new_events()
        await session.commit()
        before = incidents[0].priority

        session.add(ComplianceException(
            id=uuid.uuid4(), account_id=acct, framework="CIS_AWS", control_id="1.1",
            resource_id="i-1", reason="accept_risk", owner="sec",
        ))
        await session.commit()
        after = (await svc.recompute_priority(incidents[0].id)).priority
        assert after < before
