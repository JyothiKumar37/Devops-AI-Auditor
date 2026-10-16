"""HMAC signature + replay verification for inbound security webhooks.

Sources that deliver events over HTTP (CI/CD, Falco sidecars, Alertmanager
proxies) authenticate with a shared secret. The sender computes
``HMAC-SHA256(secret, "<timestamp>.<raw-body>")`` and sends it in a signature
header alongside the timestamp. We recompute and compare in constant time, and
reject timestamps outside a bounded window to defeat replay.

This mirrors the SCM webhook model (Phase 2) but is self-contained so security
sources can use their own per-source secret.
"""

from __future__ import annotations

import hashlib
import hmac
import time

from core.exceptions import AppError


class WebhookAuthError(AppError):
    """Inbound webhook failed authentication (bad signature / replay / missing)."""

    status_code = 401
    code = "webhook_auth_failed"


def compute_signature(secret: str, timestamp: str, body: bytes) -> str:
    """Return the hex HMAC-SHA256 over ``"<timestamp>.<body>"``."""
    mac = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
    mac.update(timestamp.encode("utf-8"))
    mac.update(b".")
    mac.update(body)
    return mac.hexdigest()


def verify_webhook(
    *,
    secret: str,
    body: bytes,
    signature: str | None,
    timestamp: str | None,
    replay_window_seconds: int,
    now: float | None = None,
) -> None:
    """Validate signature + freshness, raising :class:`WebhookAuthError` on failure.

    - ``secret`` must be configured (empty secret => reject, never accept blindly).
    - ``signature`` may be ``sha256=<hex>`` or a bare hex digest.
    - ``timestamp`` must be a unix epoch seconds within ``replay_window_seconds``.
    """
    if not secret:
        raise WebhookAuthError("This source has no signing secret configured.")
    if not signature:
        raise WebhookAuthError("Missing webhook signature.")
    if not timestamp:
        raise WebhookAuthError("Missing webhook timestamp.")

    try:
        ts = float(timestamp)
    except ValueError as exc:
        raise WebhookAuthError("Invalid webhook timestamp.") from exc

    current = time.time() if now is None else now
    if abs(current - ts) > replay_window_seconds:
        raise WebhookAuthError("Webhook timestamp outside the accepted window (replay?).")

    provided = signature.split("=", 1)[1] if signature.startswith("sha256=") else signature
    expected = compute_signature(secret, timestamp, body)
    if not hmac.compare_digest(provided, expected):
        raise WebhookAuthError("Webhook signature mismatch.")
