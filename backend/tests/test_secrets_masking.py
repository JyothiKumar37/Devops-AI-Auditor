"""Tests for the secret masking utilities."""

from __future__ import annotations

from scanners.secrets.masking import mask_in_text, mask_secret, shannon_entropy


def test_mask_reveals_only_prefix_and_suffix() -> None:
    masked = mask_secret("AKIAIOSFODNN71234", keep_start=4, keep_end=4)
    assert masked.startswith("AKIA")
    assert masked.endswith("1234")
    assert "IOSFODNN7" not in masked
    assert "*" in masked


def test_mask_does_not_reveal_true_length() -> None:
    short = mask_secret("A" * 20)
    long = mask_secret("A" * 200)
    # Fixed number of asterisks regardless of secret length.
    assert short.count("*") == long.count("*")


def test_short_values_are_fully_masked() -> None:
    assert set(mask_secret("abcd")) == {"*"}


def test_mask_in_text_replaces_all_occurrences() -> None:
    text = "token=SuperSecretValue123 again SuperSecretValue123"
    masked = mask_in_text(text, "SuperSecretValue123")
    assert "SuperSecretValue123" not in masked


def test_entropy_ordering() -> None:
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("aB3$xR9zQ1")
