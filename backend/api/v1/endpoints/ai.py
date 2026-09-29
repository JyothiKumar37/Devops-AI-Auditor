"""Interactive AI assistance endpoints.

Thin HTTP layer over `AiAssistService`. Every route requires a configured LLM
provider (503 otherwise) and is grounded in the scan's stored data. None of these
mutate the scan or apply fixes - the fix-suggestion route returns a review-only
diff.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response, status

from api.dependencies import AiAssistServiceDep
from models.schemas import (
    AiAnswer,
    AiExplanation,
    AiFixSuggestion,
    AiPriorities,
    AiScanSummary,
    AiTriage,
    AskRequest,
    ChatHistory,
    ChatMessageRead,
)

router = APIRouter(prefix="/scans", tags=["ai"])


def _history(scan_id: uuid.UUID, messages: list) -> ChatHistory:
    return ChatHistory(
        scan_id=scan_id,
        messages=[ChatMessageRead.model_validate(m) for m in messages],
    )


@router.post(
    "/{scan_id}/findings/{finding_id}/explain",
    response_model=AiExplanation,
    summary="AI explanation of a finding (impact + fix)",
)
async def explain_finding(
    scan_id: uuid.UUID, finding_id: uuid.UUID, service: AiAssistServiceDep
) -> AiExplanation:
    return AiExplanation(explanation=await service.explain_finding(scan_id, finding_id))


@router.post(
    "/{scan_id}/findings/{finding_id}/fix-suggestion",
    response_model=AiFixSuggestion,
    summary="AI-proposed fix for a finding (review-only, not applied)",
)
async def suggest_fix(
    scan_id: uuid.UUID, finding_id: uuid.UUID, service: AiAssistServiceDep
) -> AiFixSuggestion:
    return AiFixSuggestion.model_validate(await service.suggest_fix(scan_id, finding_id))


@router.post(
    "/{scan_id}/findings/{finding_id}/triage",
    response_model=AiTriage,
    summary="AI false-positive triage of a finding",
)
async def triage_finding(
    scan_id: uuid.UUID, finding_id: uuid.UUID, service: AiAssistServiceDep
) -> AiTriage:
    return AiTriage.model_validate(await service.triage_finding(scan_id, finding_id))


@router.get(
    "/{scan_id}/ai-summary",
    response_model=AiScanSummary,
    summary="AI executive summary of the scan",
)
async def scan_summary(scan_id: uuid.UUID, service: AiAssistServiceDep) -> AiScanSummary:
    return AiScanSummary(summary=await service.summarize_scan(scan_id))


@router.get(
    "/{scan_id}/priorities",
    response_model=AiPriorities,
    summary="AI context-aware risk ranking of findings",
)
async def priorities(scan_id: uuid.UUID, service: AiAssistServiceDep) -> AiPriorities:
    return AiPriorities.model_validate({"items": await service.prioritize(scan_id)})


@router.post(
    "/{scan_id}/ask",
    response_model=AiAnswer,
    summary="Ask a question about the scan (grounded in its findings)",
)
async def ask(
    scan_id: uuid.UUID, request: AskRequest, service: AiAssistServiceDep
) -> AiAnswer:
    return AiAnswer(answer=await service.ask(scan_id, request.question))


@router.get(
    "/{scan_id}/chat",
    response_model=ChatHistory,
    summary="Get the scan's AI conversation history",
)
async def get_chat(scan_id: uuid.UUID, service: AiAssistServiceDep) -> ChatHistory:
    return _history(scan_id, await service.list_chat(scan_id))


@router.post(
    "/{scan_id}/chat",
    response_model=ChatHistory,
    summary="Ask a question in the scan's persistent chat (grounded, with history)",
)
async def post_chat(
    scan_id: uuid.UUID, request: AskRequest, service: AiAssistServiceDep
) -> ChatHistory:
    return _history(scan_id, await service.post_chat(scan_id, request.question))


@router.delete(
    "/{scan_id}/chat",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Clear the scan's AI conversation history",
)
async def clear_chat(scan_id: uuid.UUID, service: AiAssistServiceDep) -> Response:
    await service.clear_chat(scan_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
