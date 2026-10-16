"""Terraform <-> AWS drift correlation (Phase 4).

Correlates the Terraform in a repository scan against a cloud account's live
assets, classifies drift, and persists the results. Read-only: it never changes
Terraform or AWS.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.exceptions import NotFoundError
from models.cloud import CloudAccount, CloudAsset, CloudDrift
from models.scan import RepositoryFile, Scan
from services.aws.drift import LiveAsset, compute_drift, parse_terraform_resources


class CloudDriftService:
    """Correlate Terraform (expected) against AWS (actual) and store drift."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    async def correlate(self, account_pk: uuid.UUID, scan_id: uuid.UUID) -> list[CloudDrift]:
        account = await self._session.get(CloudAccount, account_pk)
        if account is None:
            raise NotFoundError(f"Cloud account {account_pk} not found.")
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found.")

        tf_files = [
            (path, content)
            for (path, content) in (
                await self._session.execute(
                    select(RepositoryFile.path, RepositoryFile.content).where(
                        RepositoryFile.scan_id == scan_id,
                        RepositoryFile.file_type == "terraform",
                    )
                )
            ).all()
            if content
        ]
        resources = parse_terraform_resources(tf_files)

        assets = await self._session.scalars(
            select(CloudAsset).where(CloudAsset.account_id == account_pk)
        )
        live = [
            LiveAsset(
                service=a.service, resource_type=a.resource_type,
                resource_id=a.resource_id, name=a.name, tags=a.tags,
                attributes=a.attributes,
            )
            for a in assets.all()
        ]

        records = compute_drift(resources, live)
        await self._session.execute(
            delete(CloudDrift).where(CloudDrift.account_id == account_pk)
        )
        rows: list[CloudDrift] = []
        for rec in records:
            row = CloudDrift(
                id=uuid.uuid4(), account_id=account_pk, resource_id=rec.resource_id,
                service=rec.service, terraform_address=rec.terraform_address,
                status=rec.status, expected=rec.expected, actual=rec.actual,
                differences=rec.differences,
            )
            self._session.add(row)
            rows.append(row)
        await self._session.flush()
        return rows

    async def list_drift(
        self, account_pk: uuid.UUID, *, status: str | None = None
    ) -> Sequence[CloudDrift]:
        query = select(CloudDrift).where(CloudDrift.account_id == account_pk)
        if status:
            query = query.where(CloudDrift.status == status)
        return (await self._session.scalars(query)).all()
