"""Terraform (HCL) parsing with a lightweight line index.

`python-hcl2` gives us clean nested structure but no source positions, so we pair
it with a small brace-tracking line index that records where each top-level block
(and, on demand, an attribute within it) appears. That lets findings carry
accurate line numbers and evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import hcl2

_HEADER_RE = re.compile(
    r"^\s*(resource|data|variable|output|provider|module|locals|terraform)\b(.*)$"
)
_QUOTED_RE = re.compile(r'"([^"]*)"')


class TerraformSyntaxError(Exception):
    """Raised when an HCL file cannot be parsed."""

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.line = line


@dataclass(frozen=True, slots=True)
class Block:
    kind: str
    labels: tuple[str, ...]
    start_line: int
    end_line: int


@dataclass
class LineIndex:
    """Maps blocks (and attributes within them) to source line numbers."""

    text: str
    blocks: list[Block] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._lines = self.text.splitlines()
        self._index_blocks()

    def _index_blocks(self) -> None:
        depth = 0
        current: tuple[str, tuple[str, ...], int] | None = None
        opened = False
        for i, raw in enumerate(self._lines):
            line_no = i + 1
            opens = raw.count("{")
            closes = raw.count("}")

            if current is None and depth == 0:
                match = _HEADER_RE.match(raw)
                if match and (opens > 0 or self._opens_soon(i)):
                    kind = match.group(1)
                    labels = tuple(_QUOTED_RE.findall(match.group(2)))
                    current = (kind, labels, line_no)
                    opened = False

            depth += opens - closes

            if current is not None:
                if depth > 0:
                    opened = True
                if opened and depth <= 0:
                    self.blocks.append(
                        Block(
                            kind=current[0],
                            labels=current[1],
                            start_line=current[2],
                            end_line=line_no,
                        )
                    )
                    current = None
                    opened = False
                    depth = 0

    def _opens_soon(self, index: int) -> bool:
        # A header whose opening brace is on the next non-empty line.
        for raw in self._lines[index + 1 : index + 3]:
            if raw.strip():
                return raw.strip().startswith("{") or raw.strip() == "{"
        return False

    def block_line(self, kind: str, *labels: str) -> int | None:
        wanted = tuple(labels)
        for block in self.blocks:
            if block.kind == kind and block.labels == wanted:
                return block.start_line
        return None

    def block_range(self, kind: str, *labels: str) -> tuple[int, int] | None:
        wanted = tuple(labels)
        for block in self.blocks:
            if block.kind == kind and block.labels == wanted:
                return block.start_line, block.end_line
        return None

    def attr_line(self, start: int | None, end: int | None, key: str) -> int | None:
        """Return the line of `key = ...` or `key {` within [start, end]."""
        if start is None:
            return None
        end = end or len(self._lines)
        pattern = re.compile(rf"^\s*{re.escape(key)}\s*[=({{]")
        for i in range(start - 1, min(end, len(self._lines))):
            if pattern.match(self._lines[i]):
                return i + 1
        return start


def parse_hcl(text: str) -> dict:
    """Parse HCL text into a dict, raising `TerraformSyntaxError` on failure."""
    try:
        return hcl2.loads(text)
    except Exception as exc:  # noqa: BLE001 - hcl2/lark raise varied exception types
        raise TerraformSyntaxError(str(exc).strip() or "Invalid HCL") from exc
