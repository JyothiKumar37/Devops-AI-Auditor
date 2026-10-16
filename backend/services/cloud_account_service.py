"""Management of connected AWS cloud accounts (Phase 4, read-only).

Connecting an account assumes its read-only role to confirm access, then stores
the account by its AWS-verified account id. The external id is encrypted at rest
(Fernet); no AWS access keys are ever stored. Every state change is audited.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.crypto import require_cipher
from core.exceptions import NotFoundError, ValidationError
from core.logging import get_logger
from models.cloud import CloudAccount
from services.audit_service import AuditService
from services.aws.client import AWSClientFactory, validate_role_arn

logger = get_logger(__name__)

# A conservative region allowlist shape-check (does not call AWS).
_REGION_PREFIXES = (
    "us-", "eu-", "ap-", "sa-", "ca-", "me-", "af-", "il-", "us-gov-", "cn-",
)


def _factory_builder(settings: Settings) -> AWSClientFactory:
    """Module-level indirection so tests can inject a stubbed STS client."""
    return AWSClientFactory(settings)


# Rebindable by tests (monkeypatch cloud_account_service.build_factory).
build_factory = _factory_builder


class CloudAccountService:
    """Connect, validate, list and disconnect AWS accounts."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings
        self._audit = AuditService(session)

    async def connect(
        self,
        *,
        name: str,
        role_arn: str,
        external_id: str | None,
        regions: list[str],
    ) -> CloudAccount:
        validate_role_arn(role_arn)
        clean_regions = self._validate_regions(regions)
        cipher = require_cipher(self._settings)  # 503 if encryption not configured

        # Prove access and get the AUTHORITATIVE account id from AWS (never trust
        # a client-supplied account id).
        factory = build_factory(self._settings)
        identity = factory.verify(role_arn, external_id)
        account_id = identity["account_id"]

        existing = await self._session.scalar(
            select(CloudAccount).where(
                CloudAccount.provider == "aws", CloudAccount.account_id == account_id
            )
        )
        if existing is not None:
            raise ValidationError(f"AWS account {account_id} is already connected.")

        account = CloudAccount(
            id=uuid.uuid4(),
            provider="aws",
            name=name.strip() or account_id,
            account_id=account_id,
            role_arn=role_arn.strip(),
            encrypted_external_id=cipher.encrypt(external_id) if external_id else None,
            regions=clean_regions,
            status="connected",
            status_detail=f"Connected as {identity['arn']}",
        )
        self._session.add(account)
        await self._session.flush()
        await self._audit.record(
            "cloud.account.connect",
            resource_type="cloud_account",
            resource_id=str(account.id),
            detail={"provider": "aws", "account_id": account_id, "regions": clean_regions},
        )
        logger.info("cloud_account_connected", account_id=account_id)
        return account

    async def validate(self, account_pk: uuid.UUID) -> CloudAccount:
        """Re-assume the role to refresh connection status."""
        account = await self.get(account_pk)
        factory = build_factory(self._settings)
        external_id = self._decrypt_external_id(account)
        try:
            identity = factory.verify(account.role_arn, external_id)
            account.status = "connected"
            account.status_detail = f"Verified as {identity['arn']}"
        except Exception as exc:  # noqa: BLE001 - record status, surface detail
            account.status = "error"
            account.status_detail = str(exc)[:500]
        await self._session.flush()
        return account

    async def get(self, account_pk: uuid.UUID) -> CloudAccount:
        account = await self._session.get(CloudAccount, account_pk)
        if account is None:
            raise NotFoundError(f"Cloud account {account_pk} not found.")
        return account

    async def list_accounts(self) -> Sequence[CloudAccount]:
        return (
            await self._session.scalars(
                select(CloudAccount).order_by(CloudAccount.created_at.desc())
            )
        ).all()

    async def delete(self, account_pk: uuid.UUID) -> None:
        account = await self.get(account_pk)
        await self._audit.record(
            "cloud.account.disconnect",
            resource_type="cloud_account",
            resource_id=str(account_pk),
            detail={"provider": account.provider, "account_id": account.account_id},
        )
        await self._session.delete(account)

    # ---- helpers ----------------------------------------------------------

    def _decrypt_external_id(self, account: CloudAccount) -> str | None:
        if not account.encrypted_external_id:
            return None
        return require_cipher(self._settings).decrypt(account.encrypted_external_id)

    @staticmethod
    def _validate_regions(regions: list[str]) -> list[str]:
        clean = [r.strip() for r in dict.fromkeys(regions) if r.strip()]
        if not clean:
            raise ValidationError("At least one AWS region is required.")
        for region in clean:
            if not region.startswith(_REGION_PREFIXES) or len(region) > 32:
                raise ValidationError(f"'{region}' is not a valid AWS region.")
        return clean
