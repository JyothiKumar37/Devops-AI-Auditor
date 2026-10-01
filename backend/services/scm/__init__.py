"""SCM provider abstraction and factory.

``build_provider`` returns a configured provider for a given provider id. The
concrete GitHub/GitLab implementations are imported lazily so this package has no
hard import-time dependency on them (and tests can use the fake provider alone).
"""

from __future__ import annotations

from core.config import Settings
from services.scm.base import (
    ChangeStatus,
    CommitStatusState,
    SCMChangedFile,
    SCMComment,
    SCMError,
    SCMProvider,
    SCMPullRequest,
    SCMRepo,
    WebhookEvent,
)

SUPPORTED_PROVIDERS = ("github", "gitlab")


def build_provider(provider: str, token: str, settings: Settings) -> SCMProvider:
    """Instantiate a concrete provider by id with an access token."""
    key = (provider or "").lower()
    if key == "github":
        from services.scm.github import GitHubProvider

        return GitHubProvider(token=token, api_url=settings.github_api_url)
    if key == "gitlab":
        from services.scm.gitlab import GitLabProvider

        return GitLabProvider(token=token, api_url=settings.gitlab_api_url)
    raise SCMError(f"Unsupported SCM provider '{provider}'.", status_code=400)


__all__ = [
    "ChangeStatus",
    "CommitStatusState",
    "SCMChangedFile",
    "SCMComment",
    "SCMError",
    "SCMProvider",
    "SCMPullRequest",
    "SCMRepo",
    "SUPPORTED_PROVIDERS",
    "WebhookEvent",
    "build_provider",
]
