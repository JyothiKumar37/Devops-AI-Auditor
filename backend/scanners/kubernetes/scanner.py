"""The Kubernetes scanner (whole-repository).

Unlike the Docker/Compose scanners, this analyses *all* manifests together so it
can perform cross-file relationship analysis. It parses every manifest into a
resource model, runs the deterministic per-resource and relationship rules, and
augments them with the optional external tools when available.
"""

from __future__ import annotations

from pathlib import Path

from core.config import Settings
from core.logging import get_logger
from scanners.finding import RuleFinding
from scanners.kubernetes import tools
from scanners.kubernetes.model import K8sModel, K8sResource
from scanners.kubernetes.relationships import analyze_relationships
from scanners.kubernetes.rules import Emitter, analyze_resource, make_syntax_finding
from scanners.yaml_lines import YamlSyntaxError, load_documents

logger = get_logger(__name__)


class KubernetesScanner:
    """Analyses a set of Kubernetes manifests together."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings

    def analyze_manifests(self, files: list[tuple[str, str]]) -> list[RuleFinding]:
        """Deterministic, IO-free analysis of (file_path, text) manifests.

        Used directly by tests. Parses all documents, builds the model, and runs
        per-resource + relationship rules.
        """
        resources: list[K8sResource] = []
        syntax_findings: list[RuleFinding] = []

        for file_path, text in files:
            try:
                documents = load_documents(text)
            except YamlSyntaxError as exc:
                syntax_findings.append(make_syntax_finding(file_path, exc.message, exc.line))
                continue
            for index, document in enumerate(_expand_lists(documents)):
                if isinstance(document, dict) and document.get("kind") and document.get(
                    "apiVersion"
                ):
                    resources.append(K8sResource(document, file_path, index))

        model = K8sModel(resources)
        emit = Emitter()
        for resource in resources:
            analyze_resource(resource, emit)
        analyze_relationships(model, emit)

        return syntax_findings + emit.findings

    def analyze_repo(self, repo_root: Path, relative_paths: list[str]) -> list[RuleFinding]:
        """Analyse manifests on disk and add external-tool findings when enabled."""
        files: list[tuple[str, str]] = []
        for rel in relative_paths:
            try:
                text = (repo_root / rel).read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                logger.warning("k8s_read_failed", path=rel, error=str(exc))
                continue
            files.append((rel, text))

        findings = self.analyze_manifests(files)
        findings += self._run_external_tools(repo_root, relative_paths)
        return findings

    def _run_external_tools(self, repo_root: Path, relative_paths: list[str]) -> list[RuleFinding]:
        settings = self._settings
        timeout = settings.external_tool_timeout if settings else 120
        findings: list[RuleFinding] = []

        if (settings is None or settings.k8s_enable_kubeconform) and tools.kubeconform_available():
            for rel in relative_paths:
                findings += tools.run_kubeconform(repo_root / rel, rel, timeout=timeout)

        if (settings is None or settings.k8s_enable_kubelinter) and tools.kubelinter_available():
            findings += tools.run_kubelinter(repo_root, timeout=timeout)

        if settings is not None and settings.k8s_enable_trivy and tools.trivy_available():
            findings += tools.run_trivy_config(repo_root, timeout=timeout)

        return findings


def _expand_lists(documents: list) -> list:
    """Expand `kind: List` documents into their individual items."""
    expanded: list = []
    for document in documents:
        if isinstance(document, dict) and document.get("kind") == "List":
            expanded.extend(document.get("items", []) or [])
        else:
            expanded.append(document)
    return expanded
