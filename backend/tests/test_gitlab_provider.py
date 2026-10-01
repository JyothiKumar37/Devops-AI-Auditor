"""Tests for GitLabProvider using a mocked HTTP transport (no network)."""

from __future__ import annotations

import httpx
import pytest

from services.scm.base import ChangeStatus, CommitStatusState, SCMError, SCMRepo
from services.scm.gitlab import GitLabProvider

PROJECT_JSON = {
    "id": 99,
    "path": "web",
    "path_with_namespace": "acme/web",
    "default_branch": "main",
    "http_url_to_repo": "https://gitlab.com/acme/web.git",
    "web_url": "https://gitlab.com/acme/web",
    "visibility": "private",
}


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    method = request.method
    if path == "/api/v4/user":
        return httpx.Response(200, json={"username": "acme-bot"})
    if path.endswith("/merge_requests/5") and method == "GET":
        return httpx.Response(200, json={
            "iid": 5, "title": "Add", "state": "opened",
            "target_branch": "main", "source_branch": "feat", "sha": "head9",
            "diff_refs": {"base_sha": "base9", "head_sha": "head9"},
            "author": {"username": "dev"}, "web_url": "https://gitlab.com/acme/web/-/merge_requests/5",
        })
    if path.endswith("/merge_requests/5/changes") and method == "GET":
        return httpx.Response(200, json={"changes": [
            {"old_path": "Dockerfile", "new_path": "Dockerfile"},
            {"old_path": "k8s/app.yaml", "new_path": "k8s/app.yaml", "new_file": True},
            {"old_path": "old.yml", "new_path": "new.yml", "renamed_file": True},
        ]})
    if path.endswith("/merge_requests/5/notes") and method == "GET":
        return httpx.Response(200, json=[{"id": 1, "body": "hi", "author": {"username": "x"}}])
    if path.endswith("/merge_requests/5/notes") and method == "POST":
        return httpx.Response(201, json={"id": 77})
    if "/merge_requests/5/notes/77" in path and method == "PUT":
        return httpx.Response(200, json={"id": 77})
    if "/statuses/head9" in path and method == "POST":
        return httpx.Response(201, json={"id": 1})
    if path.endswith("/hooks") and method == "POST":
        return httpx.Response(201, json={"id": 321})
    if path == "/api/v4/projects" and method == "GET":
        return httpx.Response(200, json=[PROJECT_JSON])
    if "/projects/" in path and method == "GET":
        # get_repository (URL-encoded project ref)
        return httpx.Response(200, json=PROJECT_JSON)
    return httpx.Response(500, json={"message": f"unexpected {method} {path}"})


def _provider() -> GitLabProvider:
    return GitLabProvider(token="t", transport=httpx.MockTransport(_handler))


async def test_get_account_and_repository() -> None:
    p = _provider()
    assert await p.get_account() == "acme-bot"
    repo = await p.get_repository("acme", "web")
    assert repo.full_name == "acme/web"
    assert repo.external_id == "99"
    assert repo.private is True
    await p.aclose()


async def test_merge_request_and_changes() -> None:
    p = _provider()
    repo = SCMRepo("99", "acme", "web", "main", "", "https://gitlab.com/acme/web", True)
    pr = await p.get_pull_request(repo, 5)
    assert pr.head_sha == "head9" and pr.base_ref == "main"
    files = await p.get_changed_files(repo, 5)
    by_path = {f.path: f for f in files}
    assert by_path["k8s/app.yaml"].status is ChangeStatus.ADDED
    assert by_path["new.yml"].status is ChangeStatus.RENAMED
    assert by_path["new.yml"].previous_path == "old.yml"
    await p.aclose()


async def test_notes_status_webhook() -> None:
    p = _provider()
    repo = SCMRepo("99", "acme", "web", "main", "", "https://gitlab.com/acme/web", True)
    assert await p.create_comment(repo, 5, "body") == "77"
    await p.update_comment(repo, "5:77", "updated")  # composite mr:note id
    await p.set_commit_status(
        repo, "head9", CommitStatusState.FAILURE, context="auditor", description="x"
    )
    assert await p.create_webhook(repo, "https://cb", "secret", []) == "321"
    await p.aclose()


async def test_update_comment_requires_composite_id() -> None:
    p = _provider()
    repo = SCMRepo("99", "acme", "web", "main", "", "", True)
    with pytest.raises(SCMError):
        await p.update_comment(repo, "77", "x")  # missing mr: prefix
    await p.aclose()


def test_verify_signature_token_compare() -> None:
    p = GitLabProvider(token="t")
    assert p.verify_signature("whsec", b"{}", {"x-gitlab-token": "whsec"}) is True
    assert p.verify_signature("whsec", b"{}", {"x-gitlab-token": "wrong"}) is False
    assert p.verify_signature("whsec", b"{}", {}) is False


def test_parse_merge_request_webhook() -> None:
    p = GitLabProvider(token="t")
    payload = {
        "object_kind": "merge_request",
        "project": {"id": 99, "path_with_namespace": "acme/web"},
        "object_attributes": {
            "iid": 5, "action": "open", "source_branch": "feat", "target_branch": "main",
            "last_commit": {"id": "abc"},
        },
    }
    evt = p.parse_webhook({"x-gitlab-event-uuid": "u1"}, payload)
    assert evt.event_type == "pull_request"
    assert evt.action == "opened"  # normalised from "open"
    assert evt.pr_number == 5
    assert evt.head_sha == "abc"
    assert evt.repo_full_name == "acme/web"
    assert evt.is_pr_scan_trigger is True
