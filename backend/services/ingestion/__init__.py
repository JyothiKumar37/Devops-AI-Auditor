"""Repository ingestion.

Turns a repository source - an uploaded ZIP archive or a git clone URL - into an
isolated workspace on disk. The archive extractor is hardened against path
traversal (Zip Slip), symlink escapes and archive bombs; the git cloner is
hardened against SSRF, code execution and credential leakage. Classification of
the materialised files is handled by the Repository Discovery Agent (see
`agents.discovery`).
"""

from services.ingestion.archive import (
    ArchiveError,
    ArchiveValidationError,
    ZipArchiveExtractor,
)
from services.ingestion.git import GitCloneError, GitRepositoryCloner
from services.ingestion.workspace import Workspace, WorkspaceManager

__all__ = [
    "ArchiveError",
    "ArchiveValidationError",
    "GitCloneError",
    "GitRepositoryCloner",
    "Workspace",
    "WorkspaceManager",
    "ZipArchiveExtractor",
]
