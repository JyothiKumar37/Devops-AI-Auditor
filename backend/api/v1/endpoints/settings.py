"""Runtime settings endpoints.

Currently exposes the active LLM model as a runtime-switchable value. The
override is stored in the database (shared by the API and worker) and takes
precedence over the ``LLM_MODEL`` environment default - handy for switching to a
different model when one is overloaded, without a redeploy.
"""

from __future__ import annotations

from fastapi import APIRouter

from agents.reasoning.llm import get_provider
from api.dependencies import DbSessionDep, SettingsDep
from models.schemas import LLMModelUpdate, LLMSettingsResponse
from services.runtime_config import (
    LLM_MODEL_KEY,
    get_llm_model_override,
    resolve_settings,
    set_setting,
)

router = APIRouter(prefix="/settings", tags=["settings"])


async def _llm_settings(session: DbSessionDep, settings: SettingsDep) -> LLMSettingsResponse:
    override = await get_llm_model_override(session)
    resolved = await resolve_settings(session, settings)
    return LLMSettingsResponse(
        provider=settings.llm_provider,
        model=resolved.llm_model,
        env_model=settings.llm_model,
        overridden=bool(override),
        configured=get_provider(resolved).available,
    )


@router.get("/llm", response_model=LLMSettingsResponse, summary="Get the active LLM config")
async def get_llm_settings(
    session: DbSessionDep, settings: SettingsDep
) -> LLMSettingsResponse:
    return await _llm_settings(session, settings)


@router.put(
    "/llm",
    response_model=LLMSettingsResponse,
    summary="Switch the LLM model at runtime (empty reverts to the env default)",
)
async def update_llm_model(
    payload: LLMModelUpdate, session: DbSessionDep, settings: SettingsDep
) -> LLMSettingsResponse:
    await set_setting(session, LLM_MODEL_KEY, payload.model)
    return await _llm_settings(session, settings)
