"""A small, deterministic Dockerfile parser.

Turns Dockerfile text into a list of logical instructions (with the physical
line number of each), and models multi-stage builds. It is intentionally
lightweight - just enough structure for the rule engine to reason about - and has
no external dependencies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_INSTRUCTION_RE = re.compile(r"^\s*([A-Za-z]+)\s*(.*)$", re.DOTALL)
_FROM_PLATFORM_RE = re.compile(r"^--platform=\S+\s+", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Instruction:
    """A single logical Dockerfile instruction."""

    cmd: str  # upper-cased keyword, e.g. FROM, RUN, COPY
    value: str  # the joined arguments (line continuations already merged)
    line: int  # 1-based physical line of the instruction keyword
    stage_index: int  # -1 for instructions before the first FROM


@dataclass(frozen=True, slots=True)
class FromImage:
    """Parsed representation of a FROM instruction."""

    instruction: Instruction
    image: str
    tag: str | None
    digest: str | None
    alias: str | None
    stage_index: int


@dataclass(frozen=True, slots=True)
class Dockerfile:
    """Parsed Dockerfile."""

    instructions: list[Instruction] = field(default_factory=list)
    froms: list[FromImage] = field(default_factory=list)
    stage_aliases: frozenset[str] = frozenset()

    def by_cmd(self, cmd: str) -> list[Instruction]:
        return [i for i in self.instructions if i.cmd == cmd.upper()]

    @property
    def stage_count(self) -> int:
        return len(self.froms)


def _strip_comment(line: str) -> str:
    stripped = line.strip()
    if stripped.startswith("#"):
        return ""
    return line


def _parse_from(value: str) -> tuple[str, str | None, str | None, str | None]:
    """Parse a FROM value into (image, tag, digest, alias)."""
    text = _FROM_PLATFORM_RE.sub("", value.strip())
    tokens = text.split()
    if not tokens:
        return "", None, None, None

    ref = tokens[0]
    alias: str | None = None
    if len(tokens) >= 3 and tokens[1].upper() == "AS":
        alias = tokens[2]

    digest: str | None = None
    tag: str | None = None
    image = ref
    if "@" in ref:
        image, digest = ref.split("@", 1)
    if ":" in image:
        image, tag = image.split(":", 1)
    return image, tag, digest, alias


def parse_dockerfile(text: str) -> Dockerfile:
    """Parse Dockerfile `text` into a `Dockerfile` model."""
    lines = text.splitlines()
    instructions: list[Instruction] = []

    i = 0
    stage_index = -1
    n = len(lines)
    while i < n:
        raw = lines[i]
        content = _strip_comment(raw)
        if not content.strip():
            i += 1
            continue

        start_line = i + 1  # 1-based
        # Join line continuations (a physical line ending in a backslash).
        buffer = content
        while buffer.rstrip().endswith("\\") and i + 1 < n:
            buffer = buffer.rstrip()[:-1]  # drop trailing backslash
            i += 1
            next_line = _strip_comment(lines[i])
            buffer += " " + next_line.strip()

        match = _INSTRUCTION_RE.match(buffer.strip())
        if match:
            cmd = match.group(1).upper()
            value = match.group(2).strip()
            if cmd == "FROM":
                stage_index += 1
            instructions.append(
                Instruction(cmd=cmd, value=value, line=start_line, stage_index=stage_index)
            )
        i += 1

    froms: list[FromImage] = []
    aliases: set[str] = set()
    for idx, instr in enumerate(inst for inst in instructions if inst.cmd == "FROM"):
        image, tag, digest, alias = _parse_from(instr.value)
        froms.append(
            FromImage(
                instruction=instr,
                image=image,
                tag=tag,
                digest=digest,
                alias=alias,
                stage_index=idx,
            )
        )
        if alias:
            aliases.add(alias)

    return Dockerfile(
        instructions=instructions,
        froms=froms,
        stage_aliases=frozenset(aliases),
    )
