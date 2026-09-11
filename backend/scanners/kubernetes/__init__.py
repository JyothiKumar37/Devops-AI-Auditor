"""Kubernetes manifest analysis subsystem.

Parses all manifests together into a resource model and runs deterministic
per-resource and cross-file relationship rules, plus optional external tools
(kubeconform, kube-linter, Trivy config) when available. No LLM is involved.
"""

from scanners.kubernetes.scanner import KubernetesScanner

__all__ = ["KubernetesScanner"]
