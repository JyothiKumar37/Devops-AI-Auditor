"""Service for managing SCM integrations and imported repositories.

Connecting an integration validates the supplied token by calling the provider,
then stores the token ENCRYPTED (never in plaintext, never returned by the API).
Repositories can be listed live from the provider and imported for PR scanning.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.crypto import require_cipher
from core.exceptions import NotFoundError, ValidationError
from core.logging import get_logger
from models.integration import SCMIntegration, SCMRepository
from services.audit_service import AuditService
from services.scm import SCMError, SCMProvider, SCMRepo, build_provider

logger = get_logger(__name__)

# Module-level alias so tests can monkeypatch the provider factory.
provider_factory: Callable[[str, str, Settings], SCMProvider] = build_provider


class IntegrationService:
    """Create, list, inspect and delete SCM integrations."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings
        self._audit = AuditService(session)

    async def connect(
        self, provider: str, token: str, *, name: str | None = None
    ) -> SCMIntegration:
        """Validate the token against the provider and store it encrypted."""
        if provider not in ("github", "gitlab"):
            raise ValidationError(f"Unsupported provider '{provider}'.")
        if not token.strip():
            raise ValidationError("An access token is required.")

        cipher = require_cipher(self._settings)  # 503 if integrations disabled
        prov = provider_factory(provider, token, self._settings)
        account: str | None = None
        try:
            # Prove the token works and capture the account identity best-effort.
            get_account = getattr(prov, "get_account", None)
            if get_account is not None:
                account = await get_account()
            else:
                await prov.list_repositories(limit=1)
        except SCMError as exc:
            raise ValidationError(
                f"Could not validate the {provider} token: {exc.message}"
            ) from exc
        finally:
            await prov.aclose()

        api_url = (
            self._settings.github_api_url
            if provider == "github"
            else self._settings.gitlab_api_url
        )
        integration = SCMIntegration(
            id=uuid.uuid4(),
            provider=provider,
            account=account,
            name=name or account or provider,
            status="connected",
            api_url=api_url,
            encrypted_token=cipher.encrypt(token),
        )
        self._session.add(integration)
        await self._session.flush()
        await self._audit.record(
            "integration.connect",
            resource_type="integration",
            resource_id=str(integration.id),
            detail={"provider": provider, "account": account},
        )
        logger.info("integration_connected", provider=provider, account=account)
        return integration

    async def list_integrations(self) -> Sequence[SCMIntegration]:
        return (
            await self._session.scalars(
                select(SCMIntegration).order_by(SCMIntegration.created_at.desc())
            )
        ).all()

    async def get(self, integration_id: uuid.UUID) -> SCMIntegration:
        integration = await self._session.get(SCMIntegration, integration_id)
        if integration is None:
            raise NotFoundError(f"Integration {integration_id} not found.")
        return integration

    async def delete(self, integration_id: uuid.UUID) -> None:
        integration = await self.get(integration_id)
        await self._audit.record(
            "integration.disconnect",
            resource_type="integration",
            resource_id=str(integration_id),
            detail={"provider": integration.provider, "account": integration.account},
        )
        await self._session.delete(integration)
        logger.info("integration_disconnected", provider=integration.provider)

    def _provider_for(self, integration: SCMIntegration) -> SCMProvider:
        """Build an authenticated provider by decrypting the stored token."""
        cipher = require_cipher(self._settings)
        token = cipher.decrypt(integration.encrypted_token)
        return provider_factory(integration.provider, token, self._settings)

    async def list_remote_repositories(
        self, integration_id: uuid.UUID, limit: int = 100
    ) -> list[SCMRepo]:
        """List repositories visible to the integration's token (live call)."""
        integration = await self.get(integration_id)
        prov = self._provider_for(integration)
        try:
            return await prov.list_repositories(limit=limit)
        except SCMError as exc:
            raise ValidationError(
                f"Could not list repositories: {exc.message}"
            ) from exc
        finally:
            await prov.aclose()

    async def import_repository(
        self, integration_id: uuid.UUID, owner: str, name: str
    ) -> SCMRepository:
        """Fetch a repository from the provider and persist it for scanning."""
        integration = await self.get(integration_id)
        prov = self._provider_for(integration)
        try:
            repo = await prov.get_repository(owner, name)
        except SCMError as exc:
            raise ValidationError(f"Could not import repository: {exc.message}") from exc
        finally:
            await prov.aclose()

        existing = (
            await self._session.scalars(
                select(SCMRepository).where(
                    SCMRepository.provider == integration.provider,
                    SCMRepository.full_name == repo.full_name,
                )
            )
        ).first()
        if existing is not None:
            return existing

        row = SCMRepository(
            id=uuid.uuid4(),
            integration_id=integration.id,
            provider=integration.provider,
            external_id=repo.external_id,
            owner=repo.owner,
            name=repo.name,
            full_name=repo.full_name,
            default_branch=repo.default_branch,
            clone_url=repo.clone_url,
            web_url=repo.web_url,
            private=repo.private,
        )
        self._session.add(row)
        await self._session.flush()
        logger.info("repository_imported", provider=integration.provider, repo=repo.full_name)
        return row

    async def list_imported_repositories(self) -> Sequence[SCMRepository]:
        return (
            await self._session.scalars(
                select(SCMRepository).order_by(SCMRepository.created_at.desc())
            )
        ).all()
