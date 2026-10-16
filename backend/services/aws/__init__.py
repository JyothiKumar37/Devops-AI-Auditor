"""AWS integration package (Phase 4).

Read-only access to AWS via STS AssumeRole. No long-lived AWS credentials are
ever stored or required by the application itself.
"""

from __future__ import annotations
