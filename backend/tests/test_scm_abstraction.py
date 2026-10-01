"""Tests for the SCM provider abstraction and token encryption (Milestone 1)."""

from __future__ import annotations

import hashlib
import hmac

import pytest
from cryptography.fernet import Fernet

from core.config import Settings
from core.crypto import EncryptionError, integrations_available, require_cipher
from core.exceptions import ServiceUnavailableError
from services.scm import SCMError, build_provider
from services.scm.base import ChangeStatus, CommitStatusState
from services.scm.fake import FakeSCMProvider, changed, make_pr, make_repo

# ---------------------------------------------------------------------------
# Token encryption
# ---------------------------------------------------------------------------


def _settings(**kw: object) -> Settings:
    base: dict[str, object] = {"environment": "development", "llm_provider": "none"}
    base.update(kw)
    return Settings(**base)  # type: ignore[arg-type]


def test_integrations_disabled_without_key() -> None:
    settings = _settings(integration_encryption_key="")
    assert integrations_available(settings) is False
    with pytest.raises(ServiceUnavailableError):
        require_cipher(settings)


def test_encrypt_decrypt_roundtrip() -> None:
    key = Fernet.generate_key().decode()
    cipher = require_cipher(_settings(integration_encryption_key=key))
    token = "ghp_secrettoken_value_123"
    encrypted = cipher.encrypt(token)
    assert encrypted != token  # never stored in plaintext
    assert cipher.decrypt(encrypted) == token


def test_decrypt_with_wrong_key_raises() -> None:
    enc = require_cipher(_settings(integration_encryption_key=Fernet.generate_key().decode()))
    other = require_cipher(_settings(integration_encryption_key=Fernet.generate_key().decode()))
    blob = enc.encrypt("token")
    with pytest.raises(EncryptionError):
        other.decrypt(blob)


def test_invalid_key_is_misconfiguration() -> None:
    with pytest.raises(ServiceUnavailableError):
        require_cipher(_settings(integration_encryption_key="not-a-valid-fernet-key"))


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------


def test_build_provider_unknown_raises() -> None:
    with pytest.raises(SCMError):
        build_provider("bitbucket", "token", _settings())


# ---------------------------------------------------------------------------
# Fake provider implements the full interface
# ---------------------------------------------------------------------------


@pytest.fixture
def provider() -> FakeSCMProvider:
    p = FakeSCMProvider()
    repo = make_repo()
    p.add_repo(repo)
    p.add_pr(repo, make_pr(1), [changed("Dockerfile"), changed("k8s/app.yaml", ChangeStatus.ADDED)])
    return p


async def test_fake_read_operations(provider: FakeSCMProvider) -> None:
    repo = await provider.get_repository("acme", "web")
    assert repo.full_name == "acme/web"
    pr = await provider.get_pull_request(repo, 1)
    assert pr.head_ref == "feature"
    files = await provider.get_changed_files(repo, 1)
    assert {f.path for f in files} == {"Dockerfile", "k8s/app.yaml"}


async def test_fake_comment_and_status(provider: FakeSCMProvider) -> None:
    repo = await provider.get_repository("acme", "web")
    cid = await provider.create_comment(repo, 1, "hello")
    assert any(c.id == cid for c in await provider.list_comments(repo, 1))
    await provider.update_comment(repo, cid, "updated")
    assert any(c.body == "updated" for c in await provider.list_comments(repo, 1))
    await provider.set_commit_status(
        repo, "deadbeef", CommitStatusState.FAILURE, context="auditor", description="2 new"
    )
    assert provider.statuses[-1]["state"] == "failure"


async def test_fake_missing_repo_raises(provider: FakeSCMProvider) -> None:
    with pytest.raises(SCMError):
        await provider.get_repository("acme", "missing")


def test_fake_signature_verification(provider: FakeSCMProvider) -> None:
    body = b'{"action":"opened"}'
    secret = "whsec"
    good = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert provider.verify_signature(secret, body, {"x-signature": good}) is True
    assert provider.verify_signature(secret, body, {"x-signature": "sha256=bad"}) is False
