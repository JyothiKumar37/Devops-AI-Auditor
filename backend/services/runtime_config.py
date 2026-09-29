"""Runtime configuration overrides.

A thin layer over the `app_settings` table for operator settings that can change
without a redeploy. Currently exposes the active LLM model override, which takes
precedence over the ``LLM_MODEL`` environment default and is honoured by every
provider-construction site (AI review, reasoning, the health check).
"""

from __future__ import annotations

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from models.app_setting import AppSetting

LLM_MODEL_KEY = "llm_model"


async def get_setting(session: AsyncSession, key: str) -> str | None:
    """Return a runtime setting value, or None if unset."""
    row = await session.get(AppSetting, key)
    return row.value if row is not None else None


async def set_setting(session: AsyncSession, key: str, value: str | None) -> None:
    """Set (or, when value is empty/None, clear) a runtime setting."""
    cleaned = (value or "").strip()
    if not cleaned:
        await session.execute(delete(AppSetting).where(AppSetting.key == key))
        await session.commit()
        return
    existing = await session.get(AppSetting, key)
    if existing is None:
        session.add(AppSetting(key=key, value=cleaned))
    else:
        existing.value = cleaned
    await session.commit()


async def get_llm_model_override(session: AsyncSession) -> str | None:
    """The runtime LLM model override, if one is set."""
    return await get_setting(session, LLM_MODEL_KEY)


async def resolve_settings(session: AsyncSession, settings: Settings) -> Settings:
    """Return settings with runtime overrides applied (a copy; input untouched).

    Currently only the LLM model is overridable. When no override is set the
    original settings object is returned unchanged.
    """
    model = await get_llm_model_override(session)
    if model and model != settings.llm_model:
        return settings.model_copy(update={"llm_model": model})
    return settings
