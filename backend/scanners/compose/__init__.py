"""Docker Compose analysis subsystem.

A deterministic Compose analyzer: it first validates the YAML syntax, then runs a
rule engine over the parsed model. No LLM is involved in producing findings.
"""

from scanners.compose.scanner import DockerComposeScanner

__all__ = ["DockerComposeScanner"]
