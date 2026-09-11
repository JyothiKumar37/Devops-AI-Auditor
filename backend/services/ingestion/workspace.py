"""Isolated per-scan filesystem workspaces.

Every scan gets its own directory under a configured root. Extraction happens
inside a `repo/` subdirectory so uploaded content can never collide with control
files, and the whole workspace is removed on completion or failure.
"""

from __future__ import annotations

import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from core.config import Settings
from core.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Workspace:
    """A per-scan isolated directory tree."""

    scan_id: uuid.UUID
    root: Path

    @property
    def upload_path(self) -> Path:
        """Location the raw uploaded archive is written to."""
        return self.root / "upload.bin"

    @property
    def repo_path(self) -> Path:
        """Directory the archive is safely extracted into."""
        return self.root / "repo"


class WorkspaceManager:
    """Creates and destroys isolated scan workspaces under a base root."""

    def __init__(self, settings: Settings) -> None:
        if settings.workspace_root:
            self._base = Path(settings.workspace_root)
        else:
            self._base = Path(tempfile.gettempdir()) / "devops-ai-auditor-workspaces"

    @property
    def base(self) -> Path:
        return self._base

    def create(self, scan_id: uuid.UUID) -> Workspace:
        """Create the isolated directory tree for a scan."""
        self._base.mkdir(parents=True, exist_ok=True)
        root = self._base / str(scan_id)
        # Fail if it somehow already exists to avoid mixing runs.
        root.mkdir(parents=True, exist_ok=False)
        (root / "repo").mkdir(parents=True, exist_ok=False)
        logger.info("workspace_created", scan_id=str(scan_id), root=str(root))
        return Workspace(scan_id=scan_id, root=root)

    def destroy(self, workspace: Workspace) -> None:
        """Remove a workspace and all of its contents. Never raises."""
        try:
            shutil.rmtree(workspace.root, ignore_errors=True)
            logger.info("workspace_destroyed", scan_id=str(workspace.scan_id))
        except Exception as exc:  # noqa: BLE001 - cleanup must not raise
            logger.warning(
                "workspace_destroy_failed",
                scan_id=str(workspace.scan_id),
                error=str(exc),
            )
