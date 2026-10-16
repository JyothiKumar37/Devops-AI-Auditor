"""Deterministic correlation primitives (pure, no I/O).

Correlation groups events that share an *explainable* linkage: the same affected
resource, a resource connected to another in the cloud graph, the same IAM
principal, or the same source IP. Each linkage is a ``(signal, token)`` pair; the
token is what two events must share to be grouped, and the signal names WHY. We
never group events merely because they occurred close in time - time only bounds
an otherwise-justified grouping (see the correlation window in the service).
"""

from __future__ import annotations

from collections.abc import Iterable

from models.security import SecurityEvent

# Incident statuses that remain OPEN for new events to fold into.
OPEN_STATUSES = frozenset(
    {"new", "triaging", "investigating", "containment_planned", "containment_approved"}
)

# Signal priority (strongest first) for choosing an incident's primary key.
_SIGNAL_PRIORITY = ("resource", "related_resource", "principal", "ip")


def linkage_tokens(
    event: SecurityEvent, related_resource_ids: Iterable[str] = ()
) -> list[str]:
    """Return the deterministic linkage tokens for an event.

    A token is ``"<signal>:<value>"``. ``related_resource_ids`` are resource ids
    the event's resource is connected to in the cloud relationship graph; they let
    an event about a security group correlate with an event about the instance it
    protects, for example.
    """
    tokens: list[str] = []
    if event.resource_id:
        tokens.append(f"resource:{event.account_ref}:{event.resource_id}")
    for rid in related_resource_ids:
        if rid and rid != event.resource_id:
            tokens.append(f"resource:{event.account_ref}:{rid}")
    if event.principal:
        tokens.append(f"principal:{event.account_ref}:{event.principal}")
    if event.source_ip:
        tokens.append(f"ip:{event.source_ip}")
    # Preserve order, drop duplicates.
    return list(dict.fromkeys(tokens))


def primary_key(tokens: list[str], fallback: str) -> str:
    """Pick the strongest token as an incident's stable correlation key."""
    for signal in _SIGNAL_PRIORITY:
        for token in tokens:
            if token.startswith(f"{signal}:"):
                return token
    return tokens[0] if tokens else fallback


def rationale_for(token: str) -> tuple[str, str]:
    """Return ``(signal, human_rationale)`` for a matched linkage token."""
    signal, _, value = token.partition(":")
    if signal == "resource":
        return "resource", f"Same affected resource ({value.split(':')[-1]})."
    if signal == "related_resource":
        tail = value.split(":")[-1]
        return "related_resource", f"Connected to {tail} in the cloud relationship graph."
    if signal == "principal":
        return "principal", f"Same IAM principal involved ({value.split(':')[-1]})."
    if signal == "ip":
        return "ip", f"Same source IP observed ({value})."
    return signal or "related", "Shared correlation signal."


def shared_token(event_tokens: list[str], incident_tokens: Iterable[str]) -> str | None:
    """Return the first token shared between an event and an incident (if any)."""
    incident_set = set(incident_tokens)
    for token in event_tokens:
        if token in incident_set:
            return token
    return None


def incident_title(event: SecurityEvent) -> str:
    """A concise, deterministic incident title derived from the seed event."""
    subject = event.resource_id or event.principal or event.source_ip or "resource"
    return f"{event.title} ({subject})"[:500]
