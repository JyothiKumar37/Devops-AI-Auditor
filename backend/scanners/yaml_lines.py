"""Shared line-aware YAML loading utilities for scanners.

Loads YAML into ordinary dict/list structures where every mapping is a
`LineDict` that also records the 1-based source line of each key. Supports
multi-document streams (``---``) which Kubernetes manifests commonly use.
"""

from __future__ import annotations

from typing import Any

import yaml


class YamlSyntaxError(Exception):
    """Raised when YAML cannot be parsed."""

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.line = line


class LineDict(dict):
    """A dict that remembers the source line of each of its keys."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.lines: dict[Any, int] = {}


class LineLoader(yaml.SafeLoader):
    """SafeLoader that builds `LineDict`s carrying per-key line numbers."""


def _construct_mapping(loader: LineLoader, node: yaml.MappingNode) -> LineDict:
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


LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def line_of(container: Any, key: Any) -> int | None:
    """Return the source line of `key` within `container`, if known."""
    if isinstance(container, LineDict):
        return container.lines.get(key)
    return None


def line_at(container: Any, *keys: Any) -> int | None:
    """Walk a key path and return the line of the deepest resolvable key."""
    current = container
    last_line: int | None = None
    for key in keys:
        if not isinstance(current, dict):
            return last_line
        line = line_of(current, key)
        if line is not None:
            last_line = line
        if key not in current:
            return last_line
        current = current[key]
    return last_line


def load_documents(text: str) -> list[Any]:
    """Parse a (possibly multi-document) YAML stream into line-annotated values.

    Raises `YamlSyntaxError` on invalid YAML.
    """
    try:
        return [doc for doc in yaml.load_all(text, Loader=LineLoader) if doc is not None]
    except yaml.YAMLError as exc:
        line = None
        mark = getattr(exc, "problem_mark", None)
        if mark is not None:
            line = mark.line + 1
        raise YamlSyntaxError(str(exc).strip() or "Invalid YAML", line) from exc
