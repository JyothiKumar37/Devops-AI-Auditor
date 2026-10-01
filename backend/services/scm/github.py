"""GitHub implementation of the SCM provider interface (REST v3).

Authenticated with a token (personal access token or GitHub App installation
token - both are sent as a Bearer credential). Only the small surface the
auditor needs is implemented. Webhook signatures use HMAC-SHA256 against the
``X-Hub-Signature-256`` header.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

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

_GH_STATUS_MAP = {
    "added": ChangeStatus.ADDED,
    "modified": ChangeStatus.MODIFIED,
    "removed": ChangeStatus.REMOVED,
    "renamed": ChangeStatus.RENAMED,
    "changed": ChangeStatus.MODIFIED,
    "copied": ChangeStatus.ADDED,
}


class GitHubProvider(SCMProvider):
    """Talks to the GitHub REST API on behalf of a connected integration."""

    name = "github"

    def __init__(
        self,
        token: str,
        api_url: str = "https://api.github.com",
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 20.0,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=api_url.rstrip("/"),
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "devops-ai-auditor",
            },
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
            raise SCMError(f"GitHub request failed: {exc}") from exc
        if resp.status_code == 401:
            raise SCMError("GitHub authentication failed (invalid token).", status_code=401)
        if resp.status_code == 403:
            raise SCMError("GitHub access forbidden (scope or rate limit).", status_code=403)
        if resp.status_code >= 400:
            raise SCMError(
                f"GitHub API error {resp.status_code}: {resp.text[:200]}",
                status_code=resp.status_code,
            )
        return resp

    @staticmethod
    def _repo_from_json(data: dict[str, Any]) -> SCMRepo:
        owner = (data.get("owner") or {}).get("login", "")
        return SCMRepo(
            external_id=str(data.get("id", "")),
            owner=owner,
            name=data.get("name", ""),
            default_branch=data.get("default_branch", "main"),
            clone_url=data.get("clone_url", ""),
            web_url=data.get("html_url", ""),
            private=bool(data.get("private", True)),
        )

    async def get_account(self) -> str | None:
        resp = await self._request("GET", "/user")
        return resp.json().get("login")

    async def get_repository(self, owner: str, name: str) -> SCMRepo:
        resp = await self._request("GET", f"/repos/{owner}/{name}")
        return self._repo_from_json(resp.json())

    async def list_repositories(self, limit: int = 100) -> list[SCMRepo]:
        repos: list[SCMRepo] = []
        page = 1
        while len(repos) < limit and page <= 10:
            resp = await self._request(
                "GET", "/user/repos",
                params={"per_page": 100, "page": page, "sort": "updated"},
            )
            batch = resp.json()
            if not isinstance(batch, list) or not batch:
                break
            repos.extend(self._repo_from_json(r) for r in batch)
            if len(batch) < 100:
                break
            page += 1
        return repos[:limit]

    async def get_pull_request(self, repo: SCMRepo, number: int) -> SCMPullRequest:
        resp = await self._request(
            "GET", f"/repos/{repo.owner}/{repo.name}/pulls/{number}"
        )
        data = resp.json()
        head = data.get("head") or {}
        base = data.get("base") or {}
        head_repo = head.get("repo") or {}
        return SCMPullRequest(
            number=int(data.get("number", number)),
            title=data.get("title", ""),
            state=data.get("state", "open"),
            base_ref=base.get("ref", ""),
            base_sha=base.get("sha", ""),
            head_ref=head.get("ref", ""),
            head_sha=head.get("sha", ""),
            head_clone_url=head_repo.get("clone_url", repo.clone_url),
            author=(data.get("user") or {}).get("login", ""),
            web_url=data.get("html_url", ""),
        )

    async def get_changed_files(self, repo: SCMRepo, number: int) -> list[SCMChangedFile]:
        files: list[SCMChangedFile] = []
        page = 1
        while page <= 30:  # up to 3000 files
            resp = await self._request(
                "GET", f"/repos/{repo.owner}/{repo.name}/pulls/{number}/files",
                params={"per_page": 100, "page": page},
            )
            batch = resp.json()
            if not isinstance(batch, list) or not batch:
                break
            for f in batch:
                files.append(
                    SCMChangedFile(
                        path=f.get("filename", ""),
                        status=_GH_STATUS_MAP.get(f.get("status", ""), ChangeStatus.MODIFIED),
                        previous_path=f.get("previous_filename"),
                        additions=int(f.get("additions", 0)),
                        deletions=int(f.get("deletions", 0)),
                    )
                )
            if len(batch) < 100:
                break
            page += 1
        return files

    async def list_comments(self, repo: SCMRepo, number: int) -> list[SCMComment]:
        resp = await self._request(
            "GET", f"/repos/{repo.owner}/{repo.name}/issues/{number}/comments",
            params={"per_page": 100},
        )
        return [
            SCMComment(
                id=str(c.get("id")),
                body=c.get("body", ""),
                author=(c.get("user") or {}).get("login"),
            )
            for c in resp.json()
            if isinstance(c, dict)
        ]

    async def create_comment(self, repo: SCMRepo, number: int, body: str) -> str:
        resp = await self._request(
            "POST", f"/repos/{repo.owner}/{repo.name}/issues/{number}/comments",
            json={"body": body},
        )
        return str(resp.json().get("id"))

    async def update_comment(self, repo: SCMRepo, comment_id: str, body: str) -> None:
        await self._request(
            "PATCH", f"/repos/{repo.owner}/{repo.name}/issues/comments/{comment_id}",
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
        payload: dict[str, Any] = {
            "state": state.value,
            "context": context,
            "description": description[:140],  # GitHub caps description length
        }
        if target_url:
            payload["target_url"] = target_url
        await self._request(
            "POST", f"/repos/{repo.owner}/{repo.name}/statuses/{sha}", json=payload
        )

    async def create_webhook(
        self, repo: SCMRepo, callback_url: str, secret: str, events: list[str]
    ) -> str:
        resp = await self._request(
            "POST", f"/repos/{repo.owner}/{repo.name}/hooks",
            json={
                "name": "web",
                "active": True,
                "events": events or ["pull_request"],
                "config": {
                    "url": callback_url,
                    "content_type": "json",
                    "secret": secret,
                    "insecure_ssl": "0",
                },
            },
        )
        return str(resp.json().get("id"))

    # --- webhook ------------------------------------------------------------
    def verify_signature(self, secret: str, body: bytes, headers: dict[str, str]) -> bool:
        provided = headers.get("x-hub-signature-256", "")
        if not provided or not secret:
            return False
        expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(provided, expected)

    def parse_webhook(self, headers: dict[str, str], payload: dict[str, Any]) -> WebhookEvent:
        event_type = headers.get("x-github-event", "other")
        repo = payload.get("repository") or {}
        pr = payload.get("pull_request") or {}
        head = pr.get("head") or {}
        base = pr.get("base") or {}
        return WebhookEvent(
            provider=self.name,
            delivery_id=headers.get("x-github-delivery", ""),
            event_type=event_type,
            action=payload.get("action"),
            repo_full_name=repo.get("full_name"),
            repo_external_id=str(repo["id"]) if repo.get("id") is not None else None,
            pr_number=pr.get("number"),
            head_sha=head.get("sha") or payload.get("after"),
            base_ref=base.get("ref"),
            head_ref=head.get("ref"),
            raw=payload,
        )
