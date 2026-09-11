"""Registry that maps artifact types to scanner implementations.

Concrete scanners register themselves here so the orchestrator can discover the
appropriate scanner for a given artifact type without hard-coded imports. The
registry starts empty in the foundation stage.
"""

from __future__ import annotations

from models.enums import ScannerType
from scanners.base import Scanner


class ScannerRegistry:
    """A simple type-keyed registry of scanner instances."""

    def __init__(self) -> None:
        self._scanners: dict[ScannerType, Scanner] = {}

    def register(self, scanner: Scanner) -> None:
        """Register a scanner instance, keyed by its `scanner_type`."""
        if scanner.scanner_type in self._scanners:
            raise ValueError(f"Scanner already registered for {scanner.scanner_type}")
        self._scanners[scanner.scanner_type] = scanner

    def get(self, scanner_type: ScannerType) -> Scanner | None:
        """Return the scanner for a type, or None if none is registered."""
        return self._scanners.get(scanner_type)

    def all(self) -> list[Scanner]:
        """Return all registered scanners."""
        return list(self._scanners.values())

    @property
    def registered_types(self) -> list[ScannerType]:
        return list(self._scanners.keys())


#: Process-wide registry. Concrete scanners register against this in later stages.
scanner_registry = ScannerRegistry()
