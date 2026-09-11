"""Line-aware Docker Compose YAML parser and validator.

Loads Compose YAML into ordinary dict/list structures, but every mapping is a
`LineDict` that also records the 1-based source line of each key. This lets rules
attach precise line numbers to findings while still working with plain data.

Syntax errors raise `ComposeSyntaxError` so the scanner can report them as a
finding rather than crashing.
"""

from __future__ import annotations

from typing import Any

import yaml


class ComposeSyntaxError(Exception):
    """Raised when Compose YAML cannot be parsed."""

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.line = line


class LineDict(dict):
    """A dict that remembers the source line of each of its keys."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.lines: dict[Any, int] = {}


class _LineLoader(yaml.SafeLoader):
    """SafeLoader that builds `LineDict`s carrying per-key line numbers."""


def _construct_mapping(loader: _LineLoader, node: yaml.MappingNode) -> LineDict:
    loader.flatten_mapping(node)
    result = LineDict()
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        value = loader.construct_object(value_node, deep=True)
        result[key] = value
        mark = getattr(key_node, "start_mark", None)
        if mark is not None:
            result.lines[key] = mark.line + 1
    return result


_LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def line_of(container: Any, key: Any) -> int | None:
    """Return the source line of `key` within `container`, if known."""
    if isinstance(container, LineDict):
        return container.lines.get(key)
    return None


def load_compose(text: str) -> Any:
    """Parse Compose YAML text into a line-annotated structure.

    Raises `ComposeSyntaxError` for invalid YAML.
    """
    try:
        return yaml.load(text, Loader=_LineLoader)  # noqa: S506 - custom SafeLoader subclass
    except yaml.YAMLError as exc:
        line = None
        mark = getattr(exc, "problem_mark", None)
        if mark is not None:
            line = mark.line + 1
        raise ComposeSyntaxError(str(exc).strip() or "Invalid YAML", line) from exc
