"""Safe Git repository cloning for ingestion.

Clones a remote repository into an isolated workspace so the same read-only
analysis pipeline used for uploaded ZIPs can run over it. Cloning is hardened
against the obvious abuse vectors:

- **Scheme / SSRF hygiene** - only ``http(s)`` URLs are accepted by default.
  Local paths and ``file://`` URLs are refused unless explicitly enabled (the
  test suite opts in); ``GIT_ALLOW_PROTOCOL`` further restricts git's transports.
- **Host allowlist** - an optional allowlist restricts which remotes may be
  cloned (e.g. only ``github.com``/``gitlab.com``).
- **No code execution** - the clone runs with repository hooks disabled, never
  fetches submodules, is non-interactive (no credential prompts), reads no user
  git config, and is bounded by a timeout.
- **Working tree only** - the ``.git`` directory is removed after cloning, so
  only the working tree is indexed (parity with ZIP ingestion) and no git
  internals are analysed.

Clones are shallow (``--depth 1``) and single-branch to keep them fast and small.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # noqa: S404 - invoked without a shell and with a fixed argv
from pathlib import Path
from urllib.parse import urlsplit

from core.config import Settings
from core.logging import get_logger

logger = get_logger(__name__)

_MAX_URL_LENGTH = 2048
# A git ref (branch/tag) we are willing to pass to `--branch`. Deliberately
# conservative: no leading dash (option injection), no whitespace or shell/path
# metacharacters.
_REF_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._/\-]{0,254}$")


class GitCloneError(Exception):
    """The repository URL is invalid/disallowed or the clone failed."""


class GitRepositoryCloner:
    """Clones a remote git repository into a destination directory, safely."""

    def __init__(self, settings: Settings) -> None:
        self._timeout = settings.git_clone_timeout
        self._allow_local = settings.git_allow_local_clones
        self._allowed_hosts = settings.git_allowed_hosts_set

    def validate_url(self, url: str) -> str:
        """Validate and normalise a repository URL, or raise ``GitCloneError``."""
        candidate = (url or "").strip()
        if not candidate:
            raise GitCloneError("A repository URL is required.")
        if len(candidate) > _MAX_URL_LENGTH:
            raise GitCloneError("Repository URL is too long.")

        parts = urlsplit(candidate)
        scheme = parts.scheme.lower()

        if scheme in ("http", "https"):
            host = (parts.hostname or "").lower()
            if not host:
                raise GitCloneError("Repository URL has no host.")
            if self._allowed_hosts and host not in self._allowed_hosts:
                raise GitCloneError(
                    f"Host '{host}' is not in the allowed list of clone hosts."
                )
            return candidate

        # Local paths / file:// are only permitted when explicitly enabled.
        if self._allow_local and scheme in ("", "file"):
            return candidate

        raise GitCloneError(
            f"Unsupported repository URL scheme '{scheme or 'local path'}'. "
            "Only http(s) URLs are allowed."
        )

    @staticmethod
    def repo_name_from_url(url: str) -> str:
        """Derive a human-friendly repository name from a clone URL."""
        candidate = (url or "").strip().rstrip("/")
        parts = urlsplit(candidate)
        path = parts.path or candidate
        name = path.rstrip("/").rsplit("/", 1)[-1] if path else ""
        if name.endswith(".git"):
            name = name[: -len(".git")]
        return name.strip() or "repository"

    @staticmethod
    def _validate_ref(ref: str) -> None:
        if not _REF_RE.match(ref):
            raise GitCloneError(f"Invalid branch/tag name: '{ref}'.")

    def clone(self, url: str, ref: str | None, dest: Path) -> None:
        """Clone ``url`` (optionally at ``ref``) into ``dest``.

        ``dest`` must be an existing empty directory. Raises ``GitCloneError`` on
        any validation or clone failure.
        """
        safe_url = self.validate_url(url)

        file_allow = "always" if self._allow_local else "never"
        cmd = [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            f"protocol.file.allow={file_allow}",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--no-tags",
        ]
        if ref:
            self._validate_ref(ref)
            cmd += ["--branch", ref]
        cmd += ["--", safe_url, str(dest)]

        allowed_protocols = "http:https:file" if self._allow_local else "http:https"
        # A minimal, isolated environment: HOME points inside the workspace so no
        # user git config or stored credentials are ever read, and interactive
        # credential prompts are disabled so a private repo fails fast.
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(dest.parent),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_ALLOW_PROTOCOL": allowed_protocols,
        }

        try:
            result = subprocess.run(  # noqa: S603 - fixed argv, no shell
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise GitCloneError(f"Clone timed out after {self._timeout}s.") from exc
        except FileNotFoundError as exc:
            raise GitCloneError("git executable not found on PATH.") from exc

        if result.returncode != 0:
            lines = (result.stderr or result.stdout or "").strip().splitlines()
            detail = lines[-1] if lines else f"git exited with code {result.returncode}"
            logger.warning("git_clone_failed", returncode=result.returncode, detail=detail)
            raise GitCloneError(f"Failed to clone repository: {detail}")

        # Discard git internals so only the working tree is analysed.
        shutil.rmtree(dest / ".git", ignore_errors=True)
        logger.info("git_clone_completed", ref=ref or "default")
