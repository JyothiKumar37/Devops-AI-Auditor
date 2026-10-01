"""Provider-agnostic SCM abstraction.

GitHub and GitLab differ in terminology (pull request vs merge request, statuses
vs commit status, X-Hub-Signature vs X-Gitlab-Token) but the auditor only needs a
small, common surface. ``SCMProvider`` defines that surface; ``GitHubProvider``
and ``GitLabProvider`` implement it so the rest of Phase 2 (webhook handling, PR
scanning, PR feedback) is written once against this interface.

All network methods are async (httpx). Normalised dataclasses decouple callers
from each provider's JSON shape.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SCMError(Exception):
    """A recoverable error talking to an SCM provider (network, auth, 4xx/5xx)."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class CommitStatusState(str, Enum):
    """Normalised commit-status states, mapped to each provider's vocabulary."""

    SUCCESS = "success"
    PENDING = "pending"
    FAILURE = "failure"
    ERROR = "error"


class ChangeStatus(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    REMOVED = "removed"
    RENAMED = "renamed"


@dataclass(frozen=True, slots=True)
class SCMRepo:
    """A repository as seen through a provider."""

    external_id: str
    owner: str
    name: str
    default_branch: str
    clone_url: str
    web_url: str
    private: bool = True

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


@dataclass(frozen=True, slots=True)
class SCMPullRequest:
    """A pull request (GitHub) or merge request (GitLab), normalised."""

    number: int
    title: str
    state: str
    base_ref: str
    base_sha: str
    head_ref: str
    head_sha: str
    head_clone_url: str
    author: str
    web_url: str


@dataclass(frozen=True, slots=True)
class SCMChangedFile:
    """A file changed in a pull/merge request."""

    path: str
    status: ChangeStatus
    previous_path: str | None = None
    additions: int = 0
    deletions: int = 0


@dataclass(frozen=True, slots=True)
class SCMComment:
    """An existing comment/note on a pull/merge request."""

    id: str
    body: str
    author: str | None = None


@dataclass(frozen=True, slots=True)
class WebhookEvent:
    """A normalised inbound webhook event (what the auditor acts on)."""

    provider: str
    delivery_id: str
    event_type: str  # "pull_request" | "push" | "ping" | "other"
    action: str | None  # e.g. "opened", "synchronize", "closed"
    repo_full_name: str | None
    repo_external_id: str | None
    pr_number: int | None
    head_sha: str | None
    base_ref: str | None
    head_ref: str | None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_pr_scan_trigger(self) -> bool:
        """True for actions that should (re)scan a PR."""
        return self.event_type == "pull_request" and self.action in {
            "opened", "reopened", "synchronize", "update", "open",
        }


class SCMProvider(abc.ABC):
    """Common operations the auditor needs from a source-control provider."""

    #: Short provider identifier, e.g. "github" / "gitlab".
    name: str = "scm"

    # --- read ---------------------------------------------------------------
    @abc.abstractmethod
    async def get_repository(self, owner: str, name: str) -> SCMRepo: ...

    @abc.abstractmethod
    async def list_repositories(self, limit: int = 100) -> list[SCMRepo]: ...

    @abc.abstractmethod
    async def get_pull_request(self, repo: SCMRepo, number: int) -> SCMPullRequest: ...

    @abc.abstractmethod
    async def get_changed_files(
        self, repo: SCMRepo, number: int
    ) -> list[SCMChangedFile]: ...

    @abc.abstractmethod
    async def list_comments(self, repo: SCMRepo, number: int) -> list[SCMComment]: ...

    # --- write (feedback) ---------------------------------------------------
    @abc.abstractmethod
    async def create_comment(self, repo: SCMRepo, number: int, body: str) -> str: ...

    @abc.abstractmethod
    async def update_comment(self, repo: SCMRepo, comment_id: str, body: str) -> None: ...

    @abc.abstractmethod
    async def set_commit_status(
        self,
        repo: SCMRepo,
        sha: str,
        state: CommitStatusState,
        *,
        context: str,
        description: str,
        target_url: str | None = None,
    ) -> None: ...

    @abc.abstractmethod
    async def create_webhook(
        self, repo: SCMRepo, callback_url: str, secret: str, events: list[str]
    ) -> str: ...

    # --- webhook verification (sync; no network) ----------------------------
    @abc.abstractmethod
    def verify_signature(
        self, secret: str, body: bytes, headers: dict[str, str]
    ) -> bool: ...

    @abc.abstractmethod
    def parse_webhook(self, headers: dict[str, str], payload: dict[str, Any]) -> WebhookEvent: ...

    async def aclose(self) -> None:
        """Release any underlying network client. Override if needed."""
        return None
