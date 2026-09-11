"""Tests for the line-aware Compose parser/validator."""

from __future__ import annotations

import pytest

from scanners.compose.parser import ComposeSyntaxError, LineDict, line_of, load_compose


def test_loads_line_numbers() -> None:
    text = "services:\n  web:\n    image: nginx:1.25\n"
    root = load_compose(text)
    assert isinstance(root, LineDict)
    services = root["services"]
    assert line_of(root, "services") == 1
    assert line_of(services, "web") == 2
    assert line_of(services["web"], "image") == 3


def test_invalid_yaml_raises_syntax_error() -> None:
    with pytest.raises(ComposeSyntaxError) as exc_info:
        load_compose("services:\n  web:\n  - broken: [unclosed\n")
    assert exc_info.value.line is not None


def test_line_of_on_plain_value_is_none() -> None:
    assert line_of({"a": 1}, "a") is None
