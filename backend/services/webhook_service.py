"""Inbound SCM webhook handling.

Validates and routes webhook deliveries from GitHub/GitLab:

    verify size -> parse -> resolve integration -> verify signature
    -> dedup (idempotency) -> persist event -> dispatch PR scan -> 202

The payload is only used to ROUTE to an integration; the signature then
authenticates it. Nothing in the payload is trusted before signature checking.
Dispatch is injectable so tests exercise validation without running a scan.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.crypto import TokenCipher, integrations_available
from core.exceptions import AppError, ValidationError
from core.logging import get_logger
from models.integration import SCMIntegration, SCMRepository
from models.pullrequest import WebhookEvent
from services.scm import SCMProvider, build_provider

logger = get_logger(__name__)

# Module-level aliases so tests can monkeypatch.
provider_factory: Callable[[str, str, Settings], SCMProvider] = build_provider

DispatchFn = Callable[[str, uuid.UUID, str, int], None]


class WebhookAuthError(AppError):
    status_code = 401
    code = "webhook_unauthorized"


class WebhookService:
    """Validate inbound webhooks and dispatch PR scans."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        *,
        dispatch_fn: DispatchFn | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._dispatch = dispatch_fn or self._default_dispatch

    async def handle(
        self, provider_name: str, headers: dict[str, str], body: bytes
    ) -> dict:
        if len(body) > self._settings.webhook_max_body_bytes:
            raise ValidationError(
                "Webhook payload too large.",
                status_code=413,
                code="payload_too_large",
            )
        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValidationError("Webhook payload is not valid JSON.") from exc
        if not isinstance(payload, dict):
            raise ValidationError("Webhook payload must be a JSON object.")

        integration, secret = await self._resolve(provider_name, payload)

        prov = provider_factory(provider_name, "", self._settings)
        try:
            if not prov.verify_signature(secret, body, headers):
                raise WebhookAuthError("Webhook signature verification failed.")
            event = prov.parse_webhook(headers, payload)
        finally:
            await prov.aclose()

        # Idempotency / replay protection via the unique delivery id.
        if event.delivery_id:
            exists = (
                await self._session.scalars(
                    select(WebhookEvent).where(
                        WebhookEvent.provider == provider_name,
                        WebhookEvent.delivery_id == event.delivery_id,
                    )
                )
            ).first()
            if exists is not None:
                logger.info("webhook_duplicate", provider=provider_name, delivery=event.delivery_id)
                return {"status": "duplicate", "event": event.event_type}

        record = WebhookEvent(
            id=uuid.uuid4(),
            provider=provider_name,
            delivery_id=event.delivery_id or str(uuid.uuid4()),
            event_type=event.event_type,
            action=event.action,
            repo_full_name=event.repo_full_name,
            pr_number=event.pr_number,
            processed=False,
        )
        self._session.add(record)
        await self._session.flush()

        dispatched = False
        if event.is_pr_scan_trigger and event.pr_number and event.repo_full_name:
            self._dispatch(
                provider_name, integration.id, event.repo_full_name, event.pr_number
            )
            record.processed = True
            dispatched = True

        return {
            "status": "accepted",
            "event": event.event_type,
            "action": event.action,
            "scan_dispatched": dispatched,
        }

    async def _resolve(
        self, provider_name: str, payload: dict
    ) -> tuple[SCMIntegration, str]:
        """Resolve the integration + webhook secret for this delivery."""
        if not integrations_available(self._settings):
            raise ValidationError(
                "Integrations are disabled (no encryption key configured).",
                status_code=503,
                code="integrations_disabled",
            )
        full_name = _repo_full_name(provider_name, payload)
        integration: SCMIntegration | None = None
        if full_name:
            repo = (
                await self._session.scalars(
                    select(SCMRepository).where(
                        SCMRepository.provider == provider_name,
                        SCMRepository.full_name == full_name,
                    )
                )
            ).first()
            if repo is not None:
                integration = await self._session.get(SCMIntegration, repo.integration_id)
        if integration is None:
            integration = (
                await self._session.scalars(
                    select(SCMIntegration).where(SCMIntegration.provider == provider_name)
                )
            ).first()
        if integration is None:
            raise WebhookAuthError(f"No {provider_name} integration is configured.")

        secret = self._secret_for(integration)
        if not secret:
            raise WebhookAuthError("No webhook secret is configured for this integration.")
        return integration, secret

    def _secret_for(self, integration: SCMIntegration) -> str:
        if integration.encrypted_webhook_secret and self._settings.integration_encryption_key:
            cipher = TokenCipher(self._settings.integration_encryption_key)
            return cipher.decrypt(integration.encrypted_webhook_secret)
        if integration.provider == "github":
            return self._settings.github_webhook_secret
        return self._settings.gitlab_webhook_secret

    def _default_dispatch(
        self, provider_name: str, integration_id: uuid.UUID, repo_full_name: str, pr_number: int
    ) -> None:
        """Enqueue the PR scan on the worker (async) - never block the webhook."""
        from workers.tasks import run_pr_scan

        run_pr_scan.delay(provider_name, str(integration_id), repo_full_name, pr_number)


def _repo_full_name(provider_name: str, payload: dict) -> str | None:
    if provider_name == "github":
        return (payload.get("repository") or {}).get("full_name")
    return (payload.get("project") or {}).get("path_with_namespace")
