"""Docker analysis subsystem.

A deterministic Dockerfile rule engine (the always-on primary source of findings)
plus optional Hadolint and Trivy adapters that are used only when those binaries
are available on the host. No LLM is involved in producing findings.
"""

from scanners.docker.scanner import DockerScanner

__all__ = ["DockerScanner"]
