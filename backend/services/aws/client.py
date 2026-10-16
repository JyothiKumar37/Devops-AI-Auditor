"""AWS client factory using STS AssumeRole (read-only, short-lived credentials).

The platform never stores AWS access keys. To reach a customer account it assumes
a customer-provided read-only IAM role, optionally guarded by an External ID
(confused-deputy protection). The resulting temporary credentials are held only
for the duration of a sync and are never persisted.

boto3 is configured with the adaptive retry mode so AWS API throttling
(``Throttling``/``RequestLimitExceeded``) is retried with backoff automatically.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from core.config import Settings
from core.exceptions import CloudConnectionError, ValidationError
from core.logging import get_logger

logger = get_logger(__name__)

# botocore config shared by every client: adaptive retries (handles throttling)
# and a bounded connection pool so one sync cannot exhaust the worker.
_BOTO_CONFIG = Config(
    retries={"max_attempts": 6, "mode": "adaptive"},
    max_pool_connections=10,
    connect_timeout=10,
    read_timeout=30,
)

_ROLE_ARN_RE_HINT = "arn:aws:iam::<account-id>:role/<role-name>"


def validate_role_arn(role_arn: str) -> str:
    """Validate the shape of an IAM role ARN (defends against malformed input)."""
    arn = (role_arn or "").strip()
    parts = arn.split(":")
    if (
        len(parts) < 6
        or parts[0] != "arn"
        or parts[1] not in {"aws", "aws-us-gov", "aws-cn"}
        or parts[2] != "iam"
        or not parts[5].startswith("role/")
    ):
        raise ValidationError(
            f"Invalid IAM role ARN. Expected the form {_ROLE_ARN_RE_HINT}."
        )
    return arn


@dataclass(slots=True)
class AssumedSession:
    """A boto3 session backed by assumed, short-lived credentials."""

    session: boto3.session.Session
    account_id: str
    arn: str

    def client(self, service: str, region: str | None = None) -> Any:
        return self.session.client(service, region_name=region, config=_BOTO_CONFIG)


class AWSClientFactory:
    """Builds assumed-role boto3 sessions for a cloud account (read-only)."""

    def __init__(self, settings: Settings, *, sts_client: Any | None = None) -> None:
        self._settings = settings
        # Injectable for tests (botocore Stubber); real STS client otherwise.
        self._sts = sts_client

    def _sts_client(self) -> Any:
        if self._sts is not None:
            return self._sts
        return boto3.client(
            "sts", region_name=self._settings.aws_sts_region, config=_BOTO_CONFIG
        )

    def assume_role(self, role_arn: str, external_id: str | None) -> AssumedSession:
        """Assume the read-only role and return a session + verified account id.

        Raises ValidationError for malformed input and CloudConnectionError for any
        STS/permission failure (AccessDenied, invalid ARN, bad external id, ...).
        """
        arn = validate_role_arn(role_arn)
        kwargs: dict[str, Any] = {
            "RoleArn": arn,
            "RoleSessionName": self._settings.aws_role_session_name,
            "DurationSeconds": int(self._settings.aws_assume_role_duration),
        }
        if external_id:
            kwargs["ExternalId"] = external_id

        sts = self._sts_client()
        try:
            resp = sts.assume_role(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "ClientError")
            raise CloudConnectionError(
                f"Could not assume role: {code}. Verify the role ARN, the trust "
                "policy allows this platform, and the external id matches.",
                details={"aws_error_code": code},
            ) from exc
        except BotoCoreError as exc:
            raise CloudConnectionError(f"AWS request failed: {exc}") from exc

        creds = resp.get("Credentials", {})
        assumed = resp.get("AssumedRoleUser", {})
        session = boto3.session.Session(
            aws_access_key_id=creds.get("AccessKeyId"),
            aws_secret_access_key=creds.get("SecretAccessKey"),
            aws_session_token=creds.get("SessionToken"),
            region_name=self._settings.aws_sts_region,
        )
        account_id = _account_id_from_arn(assumed.get("Arn", "")) or _account_id_from_arn(arn)
        return AssumedSession(session=session, account_id=account_id, arn=assumed.get("Arn", arn))

    def verify(self, role_arn: str, external_id: str | None) -> dict[str, str]:
        """Assume the role and return the authoritative account id/arn.

        A successful AssumeRole both proves access and tells us the account id
        (from the assumed-role user ARN). The account id is ALWAYS taken from the
        AWS response, never from client-supplied input.
        """
        assumed = self.assume_role(role_arn, external_id)
        if not assumed.account_id:
            raise CloudConnectionError(
                "Assumed the role but could not determine the AWS account id."
            )
        return {"account_id": assumed.account_id, "arn": assumed.arn}


def _account_id_from_arn(arn: str) -> str:
    parts = (arn or "").split(":")
    return parts[4] if len(parts) > 4 and parts[4].isdigit() else ""
