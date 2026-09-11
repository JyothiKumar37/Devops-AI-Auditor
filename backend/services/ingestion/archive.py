"""Safe ZIP archive extraction.

Uploaded archives are untrusted. This extractor defends against the common
archive attack classes:

- **Zip Slip / path traversal** - member paths are normalised and every target
  is verified to resolve *inside* the destination directory. Absolute paths,
  Windows drive paths, `..` components and NUL bytes are rejected.
- **Symlink escape** - entries whose Unix mode marks them as symlinks (or any
  non-regular special file) are rejected rather than materialised.
- **Archive bombs** - the number of entries, the total uncompressed size and the
  per-entry compression ratio are all capped. The total byte cap is additionally
  enforced *while streaming* so a forged header cannot bypass it.

Repository code is never executed; files are only written to disk for later
read-only indexing.
"""

from __future__ import annotations

import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path

from core.config import Settings
from core.logging import get_logger

logger = get_logger(__name__)

_CHUNK_SIZE = 64 * 1024


class ArchiveError(Exception):
    """Base class for archive processing failures."""


class ArchiveValidationError(ArchiveError):
    """The archive is malformed or has a dangerous/disallowed structure."""


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    """Outcome of a successful extraction."""

    file_count: int
    total_bytes: int


class ZipArchiveExtractor:
    """Extracts ZIP archives into a destination directory, safely."""

    def __init__(self, settings: Settings) -> None:
        self._max_files = settings.max_repository_files
        self._max_total_bytes = settings.max_uncompressed_size_bytes
        self._max_ratio = settings.max_compression_ratio

    def extract(self, archive_path: Path, dest_dir: Path) -> ExtractionResult:
        """Safely extract `archive_path` into `dest_dir`.

        Raises `ArchiveValidationError` for malformed or dangerous archives.
        """
        dest_root = dest_dir.resolve()
        if not zipfile.is_zipfile(archive_path):
            raise ArchiveValidationError("File is not a valid ZIP archive.")

        try:
            with zipfile.ZipFile(archive_path) as zf:
                members = [m for m in zf.infolist() if not self._is_dir_entry(m)]
                self._validate_manifest(members)
                total_written = 0
                for member in members:
                    total_written += self._extract_member(zf, member, dest_root, total_written)
        except zipfile.BadZipFile as exc:
            raise ArchiveValidationError(f"Corrupt ZIP archive: {exc}") from exc

        logger.info(
            "archive_extracted",
            files=len(members),
            total_bytes=total_written,
        )
        return ExtractionResult(file_count=len(members), total_bytes=total_written)

    # -- validation helpers --------------------------------------------------

    @staticmethod
    def _is_dir_entry(member: zipfile.ZipInfo) -> bool:
        return member.is_dir() or member.filename.endswith("/")

    def _validate_manifest(self, members: list[zipfile.ZipInfo]) -> None:
        """Cheap, header-based pre-checks before writing anything to disk."""
        if not members:
            raise ArchiveValidationError("Archive contains no files.")
        if len(members) > self._max_files:
            raise ArchiveValidationError(
                f"Archive has too many files ({len(members)} > {self._max_files})."
            )

        declared_total = sum(m.file_size for m in members)
        if declared_total > self._max_total_bytes:
            raise ArchiveValidationError(
                "Archive uncompressed size exceeds the configured limit."
            )

        for member in members:
            if member.compress_size > 0:
                ratio = member.file_size / member.compress_size
                if ratio > self._max_ratio:
                    raise ArchiveValidationError(
                        f"Archive entry '{member.filename}' has a suspicious "
                        f"compression ratio ({ratio:.0f}x)."
                    )

    @staticmethod
    def _safe_target(member_name: str, dest_root: Path) -> Path:
        """Resolve a member name to a path guaranteed to be inside dest_root."""
        if "\x00" in member_name:
            raise ArchiveValidationError("Archive entry name contains a NUL byte.")

        normalised = member_name.replace("\\", "/").strip()
        if not normalised:
            raise ArchiveValidationError("Archive contains an empty entry name.")
        if normalised.startswith("/"):
            raise ArchiveValidationError(f"Absolute path in archive: '{member_name}'.")
        if len(normalised) >= 2 and normalised[1] == ":":
            raise ArchiveValidationError(f"Drive-letter path in archive: '{member_name}'.")

        parts = [p for p in normalised.split("/") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            raise ArchiveValidationError(f"Path traversal in archive: '{member_name}'.")

        target = (dest_root / Path(*parts)).resolve()
        if target != dest_root and dest_root not in target.parents:
            # Belt-and-braces: reject anything that escapes the destination.
            raise ArchiveValidationError(f"Path escapes workspace: '{member_name}'.")
        return target

    def _extract_member(
        self,
        zf: zipfile.ZipFile,
        member: zipfile.ZipInfo,
        dest_root: Path,
        already_written: int,
    ) -> int:
        """Extract a single regular-file member; returns bytes written."""
        # The upper 16 bits of external_attr hold the Unix st_mode when present.
        # Many archivers store only permission bits (no S_IFMT type bits), so we
        # only act when explicit file-type bits are present.
        mode = (member.external_attr >> 16) & 0xFFFF
        file_type_bits = mode & 0o170000  # S_IFMT
        if file_type_bits:
            if stat.S_ISLNK(mode):
                raise ArchiveValidationError(
                    f"Symlink entries are not allowed: '{member.filename}'."
                )
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise ArchiveValidationError(
                    f"Non-regular file entry not allowed: '{member.filename}'."
                )

        target = self._safe_target(member.filename, dest_root)
        target.parent.mkdir(parents=True, exist_ok=True)

        written = 0
        with zf.open(member) as src, target.open("wb") as dst:
            while True:
                chunk = src.read(_CHUNK_SIZE)
                if not chunk:
                    break
                written += len(chunk)
                # Hard cap enforced against actual bytes, not the (untrusted) header.
                if already_written + written > self._max_total_bytes:
                    raise ArchiveValidationError(
                        "Archive uncompressed size exceeds the configured limit."
                    )
                dst.write(chunk)
        return written
