"""Symmetric encryption for secrets stored at rest (SCM tokens, webhook secrets).

Access tokens for GitHub/GitLab must be stored so the worker can call those APIs
later (post PR comments, set commit status), but they must never be persisted in
plaintext. This module wraps Fernet (AES-128-CBC + HMAC-SHA256 authenticated
encryption) keyed by ``INTEGRATION_ENCRYPTION_KEY``.

If no key is configured, integrations are disabled rather than storing secrets
insecurely - ``require_cipher`` raises a 503 so the API surfaces a clear error.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from core.config import Settings
from core.exceptions import AppError, ServiceUnavailableError


class EncryptionError(AppError):
    """A stored secret could not be decrypted (wrong/rotated key or tampering)."""

    status_code = 500
    code = "encryption_error"


class TokenCipher:
    """Encrypts and decrypts short secrets with a configured Fernet key."""

    def __init__(self, key: str) -> None:
        try:
            self._fernet = Fernet(key.encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise ServiceUnavailableError(
                "INTEGRATION_ENCRYPTION_KEY is not a valid Fernet key. Generate one "
                "with: python -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\".",
                code="integration_misconfigured",
            ) from exc

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise EncryptionError(
                "Stored secret could not be decrypted. The encryption key may have "
                "changed; reconnect the integration."
            ) from exc


def integrations_available(settings: Settings) -> bool:
    """True if an encryption key is configured, so secrets can be stored safely."""
    return bool(settings.integration_encryption_key)


def require_cipher(settings: Settings) -> TokenCipher:
    """Return a cipher, or raise 503 if integrations are not configured."""
    if not settings.integration_encryption_key:
        raise ServiceUnavailableError(
            "SCM integrations are disabled: set INTEGRATION_ENCRYPTION_KEY to enable "
            "secure storage of access tokens.",
            code="integrations_disabled",
        )
    return TokenCipher(settings.integration_encryption_key)
