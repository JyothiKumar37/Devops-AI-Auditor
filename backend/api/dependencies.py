"""FastAPI dependency providers.

Shared singletons (settings, database, redis, services) are created once during
application startup and stored on `app.state`. These providers expose them to
route handlers, keeping construction in one place and handlers easy to test with
overrides.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from agents.ai_assist import AiAssistService
from core.config import Settings
from core.database import Database
from core.redis import RedisClient
from services.ai_pr_review_service import AiPrReviewService
from services.ai_security_review_service import AiSecurityReviewService
from services.health_service import HealthService
from services.integration_service import IntegrationService
from services.investigation_service import InvestigationService
from services.remediation_plan_service import RemediationPlanService
from services.remediation_service import RemediationService
from services.report import ReportService
from services.scan_service import ScanService
from services.suppression_service import SuppressionService


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_database(request: Request) -> Database:
    return request.app.state.database


def get_redis(request: Request) -> RedisClient:
    return request.app.state.redis


def get_health_service(request: Request) -> HealthService:
    return request.app.state.health_service


async def get_db_session(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """Yield a transactional database session bound to the app's engine.

    Commits on success and rolls back on error, so route handlers never manage
    transaction boundaries directly.
    """
    database: Database = request.app.state.database
    async with database.sessionmaker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
DatabaseDep = Annotated[Database, Depends(get_database)]
RedisDep = Annotated[RedisClient, Depends(get_redis)]
HealthServiceDep = Annotated[HealthService, Depends(get_health_service)]
DbSessionDep = Annotated[AsyncSession, Depends(get_db_session)]


def get_scan_service(session: DbSessionDep, settings: SettingsDep) -> ScanService:
    return ScanService(session=session, settings=settings)


ScanServiceDep = Annotated[ScanService, Depends(get_scan_service)]


def get_remediation_service(
    session: DbSessionDep, settings: SettingsDep
) -> RemediationService:
    return RemediationService(session=session, settings=settings)


RemediationServiceDep = Annotated[RemediationService, Depends(get_remediation_service)]


def get_report_service(session: DbSessionDep, settings: SettingsDep) -> ReportService:
    return ReportService(session=session, settings=settings)


ReportServiceDep = Annotated[ReportService, Depends(get_report_service)]


def get_suppression_service(session: DbSessionDep) -> SuppressionService:
    return SuppressionService(session=session)


SuppressionServiceDep = Annotated[SuppressionService, Depends(get_suppression_service)]


def get_ai_assist_service(session: DbSessionDep, settings: SettingsDep) -> AiAssistService:
    return AiAssistService(session=session, settings=settings)


AiAssistServiceDep = Annotated[AiAssistService, Depends(get_ai_assist_service)]


def get_integration_service(
    session: DbSessionDep, settings: SettingsDep
) -> IntegrationService:
    return IntegrationService(session=session, settings=settings)


IntegrationServiceDep = Annotated[IntegrationService, Depends(get_integration_service)]


def get_investigation_service(
    session: DbSessionDep, settings: SettingsDep
) -> InvestigationService:
    return InvestigationService(session=session, settings=settings)


InvestigationServiceDep = Annotated[
    InvestigationService, Depends(get_investigation_service)
]


def get_remediation_plan_service(
    session: DbSessionDep, settings: SettingsDep
) -> RemediationPlanService:
    return RemediationPlanService(session=session, settings=settings)


RemediationPlanServiceDep = Annotated[
    RemediationPlanService, Depends(get_remediation_plan_service)
]


def get_ai_pr_review_service(
    session: DbSessionDep, settings: SettingsDep
) -> AiPrReviewService:
    return AiPrReviewService(session=session, settings=settings)


AiPrReviewServiceDep = Annotated[AiPrReviewService, Depends(get_ai_pr_review_service)]


def get_ai_security_review_service(
    session: DbSessionDep, settings: SettingsDep
) -> AiSecurityReviewService:
    return AiSecurityReviewService(session=session, settings=settings)


AiSecurityReviewServiceDep = Annotated[
    AiSecurityReviewService, Depends(get_ai_security_review_service)
]
