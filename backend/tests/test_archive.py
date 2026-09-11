"""Security tests for the ZIP archive extractor.

These assert that the common archive attack classes are rejected and that a
well-formed archive extracts correctly.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from core.config import Settings
from services.ingestion.archive import ArchiveValidationError, ZipArchiveExtractor


def _settings(**overrides: object) -> Settings:
    return Settings(**overrides)  # type: ignore[arg-type]


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buffer.getvalue()


def _write(tmp_path: Path, data: bytes) -> Path:
    archive = tmp_path / "upload.zip"
    archive.write_bytes(data)
    return archive


def test_extracts_valid_archive(tmp_path: Path) -> None:
    archive = _write(
        tmp_path,
        _zip_bytes({"Dockerfile": b"FROM alpine\n", "src/app.py": b"print('hi')\n"}),
    )
    dest = tmp_path / "repo"
    dest.mkdir()

    result = ZipArchiveExtractor(_settings()).extract(archive, dest)

    assert result.file_count == 2
    assert (dest / "Dockerfile").is_file()
    assert (dest / "src" / "app.py").is_file()


def test_rejects_zip_slip(tmp_path: Path) -> None:
    archive = _write(tmp_path, _zip_bytes({"../escape.txt": b"pwned"}))
    dest = tmp_path / "repo"
    dest.mkdir()

    with pytest.raises(ArchiveValidationError):
        ZipArchiveExtractor(_settings()).extract(archive, dest)
    assert not (tmp_path / "escape.txt").exists()


def test_rejects_absolute_path(tmp_path: Path) -> None:
    archive = _write(tmp_path, _zip_bytes({"/etc/passwd": b"root"}))
    dest = tmp_path / "repo"
    dest.mkdir()

    with pytest.raises(ArchiveValidationError):
        ZipArchiveExtractor(_settings()).extract(archive, dest)


def test_rejects_symlink_entry(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 << 16)  # S_IFLNK
        zf.writestr(info, "/etc/passwd")
    archive = _write(tmp_path, buffer.getvalue())
    dest = tmp_path / "repo"
    dest.mkdir()

    with pytest.raises(ArchiveValidationError):
        ZipArchiveExtractor(_settings()).extract(archive, dest)


def test_rejects_too_many_files(tmp_path: Path) -> None:
    entries = {f"file_{i}.txt": b"x" for i in range(6)}
    archive = _write(tmp_path, _zip_bytes(entries))
    dest = tmp_path / "repo"
    dest.mkdir()

    with pytest.raises(ArchiveValidationError):
        ZipArchiveExtractor(_settings(max_repository_files=5)).extract(archive, dest)


def test_rejects_oversized_or_bomb(tmp_path: Path) -> None:
    archive = _write(tmp_path, _zip_bytes({"big.bin": b"0" * (2 * 1024 * 1024)}))
    dest = tmp_path / "repo"
    dest.mkdir()

    with pytest.raises(ArchiveValidationError):
        ZipArchiveExtractor(_settings(max_uncompressed_size_mb=1)).extract(archive, dest)


def test_rejects_empty_archive(tmp_path: Path) -> None:
    archive = _write(tmp_path, _zip_bytes({}))
    dest = tmp_path / "repo"
    dest.mkdir()

    with pytest.raises(ArchiveValidationError):
        ZipArchiveExtractor(_settings()).extract(archive, dest)


def test_rejects_non_zip(tmp_path: Path) -> None:
    archive = _write(tmp_path, b"this is definitely not a zip file")
    dest = tmp_path / "repo"
    dest.mkdir()

    with pytest.raises(ArchiveValidationError):
        ZipArchiveExtractor(_settings()).extract(archive, dest)
