"""Normalized representation of a discovered AWS resource (metadata only).

Discovery functions return ``DiscoveredResource`` objects - never secret values
(no S3 object bodies, SSM parameter values, Secrets Manager values, etc.). Only
configuration metadata needed for security rules and the exposure graph is kept.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Internet-exposure classification used across rules and the network graph.
EXPOSURE_NONE = "none"
EXPOSURE_PRIVATE = "private"
EXPOSURE_PUBLIC = "public"
EXPOSURE_UNKNOWN = "unknown"


@dataclass(slots=True)
class DiscoveredResource:
    service: str                      # ec2 | vpc | s3 | rds | iam | eks | elb | ...
    resource_type: str                # instance | security-group | bucket | ...
    resource_id: str                  # natural id (i-..., sg-..., bucket name)
    arn: str = ""
    name: str = ""
    region: str = ""
    state: str = ""
    exposure: str = EXPOSURE_UNKNOWN
    tags: dict[str, str] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)


def tags_to_dict(tag_list: Any) -> dict[str, str]:
    """Convert an AWS ``[{Key,Value}]`` tag list into a plain dict."""
    out: dict[str, str] = {}
    if isinstance(tag_list, list):
        for tag in tag_list:
            if isinstance(tag, dict) and "Key" in tag:
                out[str(tag["Key"])] = str(tag.get("Value", ""))
    return out


def name_from_tags(tags: dict[str, str], fallback: str = "") -> str:
    return tags.get("Name") or fallback
