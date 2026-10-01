"""In-memory SCM provider for tests.

Implements the full ``SCMProvider`` interface without any network, recording the
side effects (created/updated comments, commit statuses, webhooks) so tests can
assert PR-feedback behaviour and comment reconciliation deterministically.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

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


class FakeSCMProvider(SCMProvider):
    """Deterministic, in-memory provider used by the test suite."""

    name = "fake"

    def __init__(self) -> None:
        self.repos: dict[str, SCMRepo] = {}
        self.pull_requests: dict[tuple[str, int], SCMPullRequest] = {}
        self.changed_files: dict[tuple[str, int], list[SCMChangedFile]] = {}
        self.comments: dict[tuple[str, int], list[SCMComment]] = {}
        self.statuses: list[dict[str, Any]] = []
        self.webhooks: list[dict[str, Any]] = []
        self._comment_seq = 0

    # --- test setup helpers -------------------------------------------------
    def add_repo(self, repo: SCMRepo) -> None:
        self.repos[repo.full_name] = repo

    def add_pr(
        self, repo: SCMRepo, pr: SCMPullRequest, changed: list[SCMChangedFile]
    ) -> None:
        self.pull_requests[(repo.full_name, pr.number)] = pr
        self.changed_files[(repo.full_name, pr.number)] = changed
        self.comments.setdefault((repo.full_name, pr.number), [])

    # --- read ---------------------------------------------------------------
    async def get_repository(self, owner: str, name: str) -> SCMRepo:
        repo = self.repos.get(f"{owner}/{name}")
        if repo is None:
            raise SCMError(f"Repository {owner}/{name} not found.", status_code=404)
        return repo

    async def list_repositories(self, limit: int = 100) -> list[SCMRepo]:
        return list(self.repos.values())[:limit]

    async def get_pull_request(self, repo: SCMRepo, number: int) -> SCMPullRequest:
        pr = self.pull_requests.get((repo.full_name, number))
        if pr is None:
            raise SCMError(f"PR #{number} not found.", status_code=404)
        return pr

    async def get_changed_files(self, repo: SCMRepo, number: int) -> list[SCMChangedFile]:
        return list(self.changed_files.get((repo.full_name, number), []))

    async def list_comments(self, repo: SCMRepo, number: int) -> list[SCMComment]:
        return list(self.comments.get((repo.full_name, number), []))

    # --- write --------------------------------------------------------------
    async def create_comment(self, repo: SCMRepo, number: int, body: str) -> str:
        self._comment_seq += 1
        cid = str(self._comment_seq)
        self.comments.setdefault((repo.full_name, number), []).append(
            SCMComment(id=cid, body=body, author="auditor")
        )
        return cid

    async def update_comment(self, repo: SCMRepo, comment_id: str, body: str) -> None:
        for items in self.comments.values():
            for i, c in enumerate(items):
                if c.id == comment_id:
                    items[i] = SCMComment(id=comment_id, body=body, author="auditor")
                    return
        raise SCMError(f"Comment {comment_id} not found.", status_code=404)

    async def set_commit_status(
        self,
        repo: SCMRepo,
        sha: str,
        state: CommitStatusState,
        *,
        context: str,
        description: str,
        target_url: str | None = None,
    ) -> None:
        self.statuses.append(
            {
                "repo": repo.full_name,
                "sha": sha,
                "state": state.value,
                "context": context,
                "description": description,
                "target_url": target_url,
            }
        )

    async def create_webhook(
        self, repo: SCMRepo, callback_url: str, secret: str, events: list[str]
    ) -> str:
        self.webhooks.append(
            {"repo": repo.full_name, "url": callback_url, "events": events}
        )
        return str(len(self.webhooks))

    # --- webhook ------------------------------------------------------------
    def verify_signature(self, secret: str, body: bytes, headers: dict[str, str]) -> bool:
        """Mimic GitHub-style HMAC-SHA256 so webhook-security tests are realistic."""
        provided = headers.get("x-signature", "")
        expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(provided, expected)

    def parse_webhook(self, headers: dict[str, str], payload: dict[str, Any]) -> WebhookEvent:
        return WebhookEvent(
            provider=self.name,
            delivery_id=headers.get("x-delivery", ""),
            event_type=headers.get("x-event", "other"),
            action=payload.get("action"),
            repo_full_name=payload.get("repo_full_name"),
            repo_external_id=payload.get("repo_external_id"),
            pr_number=payload.get("pr_number"),
            head_sha=payload.get("head_sha"),
            base_ref=payload.get("base_ref"),
            head_ref=payload.get("head_ref"),
            raw=payload,
        )


def make_repo(owner: str = "acme", name: str = "web") -> SCMRepo:
    """Convenience factory for tests."""
    return SCMRepo(
        external_id=f"{owner}/{name}",
        owner=owner,
        name=name,
        default_branch="main",
        clone_url=f"https://example.test/{owner}/{name}.git",
        web_url=f"https://example.test/{owner}/{name}",
        private=True,
    )


def make_pr(number: int = 1, head_sha: str = "deadbeef") -> SCMPullRequest:
    return SCMPullRequest(
        number=number,
        title="Add feature",
        state="open",
        base_ref="main",
        base_sha="base000",
        head_ref="feature",
        head_sha=head_sha,
        head_clone_url="https://example.test/acme/web.git",
        author="dev",
        web_url=f"https://example.test/acme/web/pull/{number}",
    )


def changed(path: str, status: ChangeStatus = ChangeStatus.MODIFIED) -> SCMChangedFile:
    return SCMChangedFile(path=path, status=status)
