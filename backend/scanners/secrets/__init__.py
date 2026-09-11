"""Secrets Detection Agent.

Deterministic, masking-first secret detection over the working tree, with an
optional Gitleaks integration. Raw secret values never leave the subsystem - all
findings carry masked evidence only. No LLM is involved.
"""

from scanners.secrets.scanner import SecretScanner

__all__ = ["SecretScanner"]
