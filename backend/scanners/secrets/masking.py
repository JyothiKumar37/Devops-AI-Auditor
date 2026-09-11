"""Masking utilities for the secrets scanner.

The cardinal rule of this subsystem: a raw secret value must never leave this
module. Everything that could reach the database, an API response or a log is
masked here first, e.g. ``AKIA************1234``.
"""

from __future__ import annotations

import math

_STARS = 12


def mask_secret(value: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """Return a masked form of `value` revealing only a short prefix/suffix.

    Uses a fixed number of asterisks so the true length is not disclosed. Very
    short values are fully masked.
    """
    if not value:
        return "*" * 8
    if len(value) <= keep_start + keep_end:
        return "*" * 8
    return f"{value[:keep_start]}{'*' * _STARS}{value[-keep_end:]}"


def mask_in_text(text: str, secret: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """Replace every occurrence of `secret` inside `text` with its masked form."""
    if not secret:
        return text
    return text.replace(secret, mask_secret(secret, keep_start, keep_end))


def shannon_entropy(value: str) -> float:
    """Shannon entropy (bits per character) of a string."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
