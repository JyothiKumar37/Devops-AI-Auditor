"""CI/CD analysis subsystem.

Deterministic analyzers for GitHub Actions, GitLab CI and Jenkins pipelines, plus
an optional actionlint adapter for GitHub Actions. No LLM is involved in producing
findings.
"""

from scanners.cicd.scanner import CICDScanner

__all__ = ["CICDScanner"]
