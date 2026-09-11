"""Repository ingestion.

Turns an uploaded artifact (currently a ZIP archive) into an isolated workspace
on disk. The archive extractor is hardened against path traversal (Zip Slip),
symlink escapes and archive bombs. Classification of the extracted files is
handled by the Repository Discovery Agent (see `agents.discovery`).
"""

from services.ingestion.archive import (
    ArchiveError,
    ArchiveValidationError,
    ZipArchiveExtractor,
)
from services.ingestion.workspace import Workspace, WorkspaceManager

__all__ = [
    "ArchiveError",
    "ArchiveValidationError",
    "Workspace",
    "WorkspaceManager",
    "ZipArchiveExtractor",
]
