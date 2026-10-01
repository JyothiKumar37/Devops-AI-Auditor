"""Tests for GitHubProvider using a mocked HTTP transport (no network)."""

from __future__ import annotations

import hashlib
import hmac
import json

import httpx
import pytest

from services.scm.base import ChangeStatus, CommitStatusState, SCMError
from services.scm.github import GitHubProvider

REPO_JSON = {
    "id": 42,
    "name": "web",
    "owner": {"login": "acme"},
    "default_branch": "main",
    "clone_url": "https://github.com/acme/web.git",
    "html_url": "https://github.com/acme/web",
    "private": True,
}


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    method = request.method
    if path == "/user" and method == "GET":
        return httpx.Response(200, json={"login": "acme-bot"})
    if path == "/repos/acme/web" and method == "GET":
        return httpx.Response(200, json=REPO_JSON)
    if path == "/user/repos" and method == "GET":
        return httpx.Response(200, json=[REPO_JSON])
    if path == "/repos/acme/web/pulls/7" and method == "GET":
        return httpx.Response(200, json={
            "number": 7, "title": "Add", "state": "open",
            "base": {"ref": "main", "sha": "base1"},
            "head": {"ref": "feat", "sha": "head1", "repo": {"clone_url": "https://github.com/acme/web.git"}},
            "user": {"login": "dev"}, "html_url": "https://github.com/acme/web/pull/7",
        })
    if path == "/repos/acme/web/pulls/7/files" and method == "GET":
        if request.url.params.get("page") == "1":
            return httpx.Response(200, json=[
                {"filename": "Dockerfile", "status": "modified", "additions": 3, "deletions": 1},
                {"filename": "k8s/app.yaml", "status": "added", "additions": 10, "deletions": 0},
            ])
        return httpx.Response(200, json=[])
    if path == "/repos/acme/web/issues/7/comments" and method == "GET":
        return httpx.Response(200, json=[{"id": 100, "body": "hi", "user": {"login": "x"}}])
    if path == "/repos/acme/web/issues/7/comments" and method == "POST":
        return httpx.Response(201, json={"id": 101})
    if path == "/repos/acme/web/issues/comments/101" and method == "PATCH":
        return httpx.Response(200, json={"id": 101})
    if path == "/repos/acme/web/statuses/head1" and method == "POST":
        return httpx.Response(201, json={"id": 1})
    if path == "/repos/acme/web/hooks" and method == "POST":
        return httpx.Response(201, json={"id": 555})
    if path == "/repos/acme/missing" and method == "GET":
        return httpx.Response(404, json={"message": "Not Found"})
    return httpx.Response(500, json={"message": f"unexpected {method} {path}"})


def _provider() -> GitHubProvider:
    return GitHubProvider(token="t", transport=httpx.MockTransport(_handler))


async def test_get_account() -> None:
    p = _provider()
    assert await p.get_account() == "acme-bot"
    await p.aclose()


async def test_get_repository() -> None:
    p = _provider()
    repo = await p.get_repository("acme", "web")
    assert repo.full_name == "acme/web"
    assert repo.default_branch == "main"
    assert repo.private is True
    await p.aclose()


async def test_list_repositories() -> None:
    p = _provider()
    repos = await p.list_repositories()
    assert len(repos) == 1 and repos[0].name == "web"
    await p.aclose()


async def test_get_pull_request_and_files() -> None:
    p = _provider()
    repo = await p.get_repository("acme", "web")
    pr = await p.get_pull_request(repo, 7)
    assert pr.head_sha == "head1" and pr.base_ref == "main"
    files = await p.get_changed_files(repo, 7)
    assert {f.path for f in files} == {"Dockerfile", "k8s/app.yaml"}
    added = next(f for f in files if f.path == "k8s/app.yaml")
    assert added.status is ChangeStatus.ADDED
    await p.aclose()


async def test_comment_and_status_and_webhook() -> None:
    p = _provider()
    repo = await p.get_repository("acme", "web")
    assert await p.create_comment(repo, 7, "body") == "101"
    await p.update_comment(repo, "101", "updated")
    await p.set_commit_status(
        repo, "head1", CommitStatusState.FAILURE, context="auditor", description="x"
    )
    assert await p.create_webhook(repo, "https://cb", "secret", ["pull_request"]) == "555"
    await p.aclose()


async def test_error_mapping() -> None:
    p = _provider()
    with pytest.raises(SCMError) as exc:
        await p.get_repository("acme", "missing")
    assert exc.value.status_code == 404
    await p.aclose()


def test_verify_signature() -> None:
    p = GitHubProvider(token="t")
    body = b'{"action":"opened"}'
    secret = "whsec"
    good = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert p.verify_signature(secret, body, {"x-hub-signature-256": good}) is True
    assert p.verify_signature(secret, body, {"x-hub-signature-256": "sha256=bad"}) is False
    assert p.verify_signature("", body, {"x-hub-signature-256": good}) is False


def test_parse_webhook() -> None:
    p = GitHubProvider(token="t")
    payload = json.loads(
        '{"action":"synchronize","number":7,'
        '"repository":{"id":42,"full_name":"acme/web"},'
        '"pull_request":{"number":7,"head":{"sha":"abc","ref":"feat"},"base":{"ref":"main"}}}'
    )
    evt = p.parse_webhook(
        {"x-github-event": "pull_request", "x-github-delivery": "d1"}, payload
    )
    assert evt.event_type == "pull_request"
    assert evt.action == "synchronize"
    assert evt.pr_number == 7
    assert evt.head_sha == "abc"
    assert evt.repo_full_name == "acme/web"
    assert evt.is_pr_scan_trigger is True
