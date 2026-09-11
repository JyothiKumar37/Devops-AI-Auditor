"""The scanner contract.

Every concrete scanner implements the `Scanner` protocol: given a `ScanContext`
(a repository path and the file paths matched for its type), it returns a list of
`Finding` objects. This keeps scanners pure, deterministic and unit-testable in
isolation from the API and the database.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path

from models.enums import ScannerType, Severity


@dataclass(frozen=True, slots=True)
class Finding:
    """A single issue discovered by a scanner."""

    scanner: ScannerType
    rule_id: str
    title: str
    severity: Severity
    file_path: str
    line: int | None = None
    remediation: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Inputs handed to a scanner for a single run."""

    repository_root: Path
    target_files: tuple[Path, ...]


class Scanner(abc.ABC):
    """Abstract base class all concrete scanners must extend."""

    #: The artifact category this scanner handles.
    scanner_type: ScannerType

    @abc.abstractmethod
    def matches(self, path: Path) -> bool:
        """Return True if `path` is an artifact this scanner should analyse."""
        raise NotImplementedError

    @abc.abstractmethod
    def scan(self, context: ScanContext) -> list[Finding]:
        """Analyse the target files and return any findings.

        Implementations must be side-effect free with respect to the repository
        contents (read-only) so they remain deterministic and testable.
        """
        raise NotImplementedError
