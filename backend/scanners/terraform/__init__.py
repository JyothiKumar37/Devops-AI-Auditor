"""Terraform analysis subsystem.

Parses HCL per module directory into a resource/variable/reference model and runs
deterministic, contextual security/reliability/infrastructure checks, plus
optional external tools (terraform fmt/validate, TFLint, Checkov, Trivy config)
when available. No LLM is involved.
"""

from scanners.terraform.scanner import TerraformScanner

__all__ = ["TerraformScanner"]
