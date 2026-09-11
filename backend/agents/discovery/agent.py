"""The Repository Discovery Agent.

Walks an extracted repository read-only and classifies every regular file. The
agent is fully deterministic (no LLM) and never executes repository code - files
are opened only to hash them and, for YAML/JSON candidates, to detect Kubernetes
manifests by content.
"""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath

from agents.discovery.classifier import DiscoveryContext, classify_file
from agents.discovery.types import DiscoveredFile, DiscoveryResult, category_for
from core.logging import get_logger

logger = get_logger(__name__)

_CHUNK_SIZE = 64 * 1024
_MAX_CONTENT_BYTES = 1024 * 1024
_CONTENT_SUFFIXES = {".yml", ".yaml", ".json"}
_CHART_FILENAMES = {"chart.yaml", "chart.yml"}


class RepositoryDiscoveryAgent:
    """Classifies the files of an extracted repository into DevOps categories."""

    def discover(self, repo_root: Path) -> DiscoveryResult:
        """Discover and classify every regular file under `repo_root`."""
        root = repo_root.resolve()
        files = [
            entry
            for entry in sorted(root.rglob("*"))
            if entry.is_file() and not entry.is_symlink()
        ]

        context = self._build_context(root, files)

        discovered: list[DiscoveredFile] = []
        for entry in files:
            relative = entry.relative_to(root).as_posix()
            checksum, size, content = self._read(entry)
            detected_type = classify_file(relative, content=content, context=context)
            discovered.append(
                DiscoveredFile(
                    path=relative,
                    detected_type=detected_type,
                    category=category_for(detected_type),
                    size=size,
                    checksum=checksum,
                )
            )

        result = DiscoveryResult(files=discovered)
        logger.info(
            "repository_discovered",
            files=len(discovered),
            charts=len(context.chart_dirs),
            counts=result.counts(),
        )
        return result

    @staticmethod
    def _build_context(root: Path, files: list[Path]) -> DiscoveryContext:
        """Identify Helm chart directories (those containing a Chart.yaml)."""
        chart_dirs: set[str] = set()
        for entry in files:
            if entry.name.lower() in _CHART_FILENAMES:
                parent = entry.parent.relative_to(root).as_posix()
                chart_dirs.add("" if parent == "." else parent)
        return DiscoveryContext(chart_dirs=frozenset(chart_dirs))

    @staticmethod
    def _read(path: Path) -> tuple[str, int, bytes | None]:
        """Return (sha256 hex, size, optional content) reading the file once.

        Content is captured only for reasonably sized YAML/JSON candidates so the
        classifier can detect Kubernetes manifests without a second read.
        """
        capture = PurePosixPath(path.name).suffix.lower() in _CONTENT_SUFFIXES
        digest = hashlib.sha256()
        size = 0
        buffer = bytearray() if capture else None

        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
                if buffer is not None and len(buffer) < _MAX_CONTENT_BYTES:
                    buffer.extend(chunk[: _MAX_CONTENT_BYTES - len(buffer)])

        content = bytes(buffer) if buffer is not None and size <= _MAX_CONTENT_BYTES else None
        return digest.hexdigest(), size, content
