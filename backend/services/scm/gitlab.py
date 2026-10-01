"""GitLab implementation of the SCM provider interface (REST v4).

Maps GitLab's merge-request vocabulary onto the common pull-request surface so
the rest of Phase 2 is provider-agnostic. Authenticated with a token sent as the
``PRIVATE-TOKEN`` header. Webhooks are validated by comparing the
``X-Gitlab-Token`` header to the stored secret (GitLab does not HMAC-sign bodies).
"""

from __future__ import annotations

import hmac
from typing import Any
from urllib.parse import quote

import httpx

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

# Normalise GitLab commit-status states.
_STATUS_MAP = {
    CommitStatusState.SUCCESS: "success",
    CommitStatusState.PENDING: "pending",
    CommitStatusState.FAILURE: "failed",
    CommitStatusState.ERROR: "failed",
}

# Normalise GitLab MR actions to the GitHub-style vocabulary used downstream.
_ACTION_MAP = {
    "open": "opened",
    "reopen": "reopened",
    "update": "synchronize",
    "close": "closed",
    "merge": "merged",
}


class GitLabProvider(SCMProvider):
    """Talks to the GitLab REST API on behalf of a connected integration."""

    name = "gitlab"

    def __init__(
        self,
        token: str,
        api_url: str = "https://gitlab.com/api/v4",
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 20.0,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=api_url.rstrip("/"),
            headers={"PRIVATE-TOKEN": token, "User-Agent": "devops-ai-auditor"},
            transport=transport,
            timeout=timeout,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(
        self, method: str, path: str, *, json: Any = None, params: Any = None
    ) -> httpx.Response:
        try:
            resp = await self._client.request(method, path, json=json, params=params)
        except httpx.HTTPError as exc:
            raise SCMError(f"GitLab request failed: {exc}") from exc
        if resp.status_code == 401:
            raise SCMError("GitLab authentication failed (invalid token).", status_code=401)
        if resp.status_code >= 400:
            raise SCMError(
                f"GitLab API error {resp.status_code}: {resp.text[:200]}",
                status_code=resp.status_code,
            )
        return resp

    @staticmethod
    def _project_ref(repo: SCMRepo) -> str:
        """Prefer the numeric project id; fall back to URL-encoded full name."""
        if repo.external_id:
            return repo.external_id
        return quote(repo.full_name, safe="")

    @staticmethod
    def _repo_from_json(data: dict[str, Any]) -> SCMRepo:
        full = data.get("path_with_namespace", "")
        owner, _, name = full.rpartition("/")
        return SCMRepo(
            external_id=str(data.get("id", "")),
            owner=owner or (data.get("namespace") or {}).get("full_path", ""),
            name=name or data.get("path", ""),
            default_branch=data.get("default_branch", "main"),
            clone_url=data.get("http_url_to_repo", ""),
            web_url=data.get("web_url", ""),
            private=data.get("visibility", "private") != "public",
        )

    async def get_account(self) -> str | None:
        resp = await self._request("GET", "/user")
        return resp.json().get("username")

    async def get_repository(self, owner: str, name: str) -> SCMRepo:
        ref = quote(f"{owner}/{name}", safe="")
        resp = await self._request("GET", f"/projects/{ref}")
        return self._repo_from_json(resp.json())

    async def list_repositories(self, limit: int = 100) -> list[SCMRepo]:
        resp = await self._request(
            "GET", "/projects",
            params={"membership": "true", "per_page": min(limit, 100),
                    "order_by": "last_activity_at"},
        )
        data = resp.json()
        if not isinstance(data, list):
            return []
        return [self._repo_from_json(r) for r in data][:limit]

    async def get_pull_request(self, repo: SCMRepo, number: int) -> SCMPullRequest:
        ref = self._project_ref(repo)
        resp = await self._request("GET", f"/projects/{ref}/merge_requests/{number}")
        data = resp.json()
        diff_refs = data.get("diff_refs") or {}
        return SCMPullRequest(
            number=int(data.get("iid", number)),
            title=data.get("title", ""),
            state=data.get("state", "opened"),
            base_ref=data.get("target_branch", ""),
            base_sha=diff_refs.get("base_sha", ""),
            head_ref=data.get("source_branch", ""),
            head_sha=data.get("sha") or diff_refs.get("head_sha", ""),
            head_clone_url=repo.clone_url,
            author=(data.get("author") or {}).get("username", ""),
            web_url=data.get("web_url", ""),
        )

    async def get_changed_files(self, repo: SCMRepo, number: int) -> list[SCMChangedFile]:
        ref = self._project_ref(repo)
        resp = await self._request(
            "GET", f"/projects/{ref}/merge_requests/{number}/changes"
        )
        changes = resp.json().get("changes", [])
        files: list[SCMChangedFile] = []
        for c in changes:
            if c.get("new_file"):
                status = ChangeStatus.ADDED
            elif c.get("deleted_file"):
                status = ChangeStatus.REMOVED
            elif c.get("renamed_file"):
                status = ChangeStatus.RENAMED
            else:
                status = ChangeStatus.MODIFIED
            files.append(
                SCMChangedFile(
                    path=c.get("new_path") or c.get("old_path", ""),
                    status=status,
                    previous_path=c.get("old_path") if c.get("renamed_file") else None,
                )
            )
        return files

    async def list_comments(self, repo: SCMRepo, number: int) -> list[SCMComment]:
        ref = self._project_ref(repo)
        resp = await self._request(
            "GET", f"/projects/{ref}/merge_requests/{number}/notes",
            params={"per_page": 100},
        )
        return [
            SCMComment(
                id=str(n.get("id")),
                body=n.get("body", ""),
                author=(n.get("author") or {}).get("username"),
            )
            for n in resp.json()
            if isinstance(n, dict)
        ]

    async def create_comment(self, repo: SCMRepo, number: int, body: str) -> str:
        ref = self._project_ref(repo)
        resp = await self._request(
            "POST", f"/projects/{ref}/merge_requests/{number}/notes",
            json={"body": body},
        )
        return str(resp.json().get("id"))

    async def update_comment(self, repo: SCMRepo, comment_id: str, body: str) -> None:
        # GitLab note updates require the MR iid in the path. The reconciliation
        # layer passes a composite "mr:note" id so we can locate it.
        if ":" in comment_id:
            mr_iid, note_id = comment_id.split(":", 1)
        else:
            raise SCMError("GitLab comment id must be 'mr:note' to update.", status_code=400)
        ref = self._project_ref(repo)
        await self._request(
            "PUT", f"/projects/{ref}/merge_requests/{mr_iid}/notes/{note_id}",
            json={"body": body},
        )

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
        ref = self._project_ref(repo)
        payload: dict[str, Any] = {
            "state": _STATUS_MAP.get(state, "failed"),
            "name": context,
            "description": description[:255],
        }
        if target_url:
            payload["target_url"] = target_url
        await self._request("POST", f"/projects/{ref}/statuses/{sha}", json=payload)

    async def create_webhook(
        self, repo: SCMRepo, callback_url: str, secret: str, events: list[str]
    ) -> str:
        ref = self._project_ref(repo)
        resp = await self._request(
            "POST", f"/projects/{ref}/hooks",
            json={
                "url": callback_url,
                "token": secret,
                "merge_requests_events": True,
                "push_events": False,
                "enable_ssl_verification": True,
            },
        )
        return str(resp.json().get("id"))

    # --- webhook ------------------------------------------------------------
    def verify_signature(self, secret: str, body: bytes, headers: dict[str, str]) -> bool:
        provided = headers.get("x-gitlab-token", "")
        if not provided or not secret:
            return False
        return hmac.compare_digest(provided, secret)

    def parse_webhook(self, headers: dict[str, str], payload: dict[str, Any]) -> WebhookEvent:
        object_kind = payload.get("object_kind", "")
        attrs = payload.get("object_attributes") or {}
        project = payload.get("project") or {}
        if object_kind == "merge_request":
            event_type = "pull_request"
            action = _ACTION_MAP.get(attrs.get("action", ""), attrs.get("action"))
            head_sha = (attrs.get("last_commit") or {}).get("id")
        elif object_kind == "push":
            event_type = "push"
            action = None
            head_sha = payload.get("after")
        else:
            event_type = object_kind or "other"
            action = None
            head_sha = None
        return WebhookEvent(
            provider=self.name,
            delivery_id=headers.get("x-gitlab-event-uuid", ""),
            event_type=event_type,
            action=action,
            repo_full_name=project.get("path_with_namespace"),
            repo_external_id=str(project["id"]) if project.get("id") is not None else None,
            pr_number=attrs.get("iid"),
            head_sha=head_sha,
            base_ref=attrs.get("target_branch"),
            head_ref=attrs.get("source_branch"),
            raw=payload,
        )
