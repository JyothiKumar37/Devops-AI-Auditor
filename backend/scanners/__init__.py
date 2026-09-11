"""Scanner abstractions.

This package defines the *contract* every artifact scanner must satisfy and a
registry to look scanners up by type. Concrete scanners (Dockerfile, Kubernetes,
Terraform, ...) are intentionally NOT implemented in the foundation stage - only
the extensible interface they will plug into.
"""

from scanners.base import Finding, ScanContext, Scanner
from scanners.registry import ScannerRegistry, scanner_registry

__all__ = ["Finding", "ScanContext", "Scanner", "ScannerRegistry", "scanner_registry"]
