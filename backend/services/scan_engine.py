"""Pure, database-free scanning engine.

Runs the deterministic scanners over an extracted repository directory and
returns the raw ``RuleFinding`` list - no persistence, no DB session, no AI. This
is the single dispatch shared by:

- the full-scan pipeline (``ScanService._run_scanners`` delegates here),
- incremental PR/MR scanning (restricted to changed files),
- the CLI (``devops-auditor scan``).

``only_paths`` restricts scanning to a set of repository-relative POSIX paths so
PR scans analyse just the changed files (whole-repo scanners like Kubernetes and
Terraform are given only the changed subset).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from agents.discovery import RepositoryDiscoveryAgent
from agents.discovery.types import DiscoveredFile, FileCategory
from core.config import Settings
from scanners.ansible import AnsibleScanner
from scanners.cicd import CICDScanner
from scanners.compose import DockerComposeScanner
from scanners.config import ConfigScanner
from scanners.docker import DockerScanner
from scanners.finding import RuleFinding
from scanners.helm import HelmScanner
from scanners.kubernetes import KubernetesScanner
from scanners.secrets import SecretScanner
from scanners.shell import ShellScanner
from scanners.terraform import TerraformScanner


def collect_rule_findings(
    repo_root: Path,
    discovered_files: list[DiscoveredFile],
    settings: Settings,
) -> list[RuleFinding]:
    """Run every applicable scanner over the discovered files (deterministic).

    This is the exact per-category dispatch the full pipeline uses, returning raw
    ``RuleFinding`` objects. Callers map them to persisted rows (full scan) or use
    them directly (PR scan / CLI).
    """
    findings: list[RuleFinding] = []

    def of(category: FileCategory) -> list[DiscoveredFile]:
        return [f for f in discovered_files if f.category == category]

    docker_files = of(FileCategory.DOCKER)
    if docker_files:
        docker = DockerScanner(settings)
        for f in docker_files:
            findings.extend(docker.analyze_file(repo_root, f.path))

    compose_files = of(FileCategory.COMPOSE)
    if compose_files:
        compose = DockerComposeScanner(settings)
        for f in compose_files:
            findings.extend(compose.analyze_file(repo_root, f.path))

    k8s_files = of(FileCategory.KUBERNETES)
    if k8s_files:
        findings.extend(
            KubernetesScanner(settings).analyze_repo(repo_root, [f.path for f in k8s_files])
        )

    tf_files = of(FileCategory.TERRAFORM)
    if tf_files:
        findings.extend(
            TerraformScanner(settings).analyze_repo(repo_root, [f.path for f in tf_files])
        )

    helm_files = of(FileCategory.HELM)
    if helm_files:
        helm = HelmScanner(settings)
        for f in helm_files:
            findings.extend(helm.analyze_file(repo_root, f.path))

    ansible_files = of(FileCategory.ANSIBLE)
    if ansible_files:
        ansible = AnsibleScanner(settings)
        for f in ansible_files:
            findings.extend(ansible.analyze_file(repo_root, f.path))

    shell_files = of(FileCategory.SHELL)
    if shell_files:
        shell = ShellScanner(settings)
        for f in shell_files:
            findings.extend(shell.analyze_file(repo_root, f.path))

    cicd_files = of(FileCategory.CICD)
    if cicd_files:
        entries = [(f.path, f.detected_type) for f in cicd_files]
        findings.extend(CICDScanner(settings).analyze_repo(repo_root, entries))

    config_files = of(FileCategory.CONFIGURATION)
    if config_files:
        config = ConfigScanner(settings)
        for f in config_files:
            findings.extend(config.analyze_file(repo_root, f.path))

    # Secret scanning runs over every provided file (secrets can appear anywhere).
    all_paths = [f.path for f in discovered_files]
    if all_paths:
        findings.extend(SecretScanner(settings).analyze_repo(repo_root, all_paths))

    return findings


def scan_repository(
    repo_root: Path,
    settings: Settings,
    *,
    only_paths: Iterable[str] | None = None,
) -> list[RuleFinding]:
    """Discover and scan a repository directory, optionally restricted to paths.

    When ``only_paths`` is given, discovery still runs over the whole tree (so
    files are classified with full repository context, e.g. Helm chart dirs) but
    scanning is limited to the listed changed files - the incremental PR path.
    """
    result = RepositoryDiscoveryAgent().discover(repo_root)
    files = result.files
    if only_paths is not None:
        wanted = {p.lstrip("./") for p in only_paths}
        files = [f for f in files if f.path in wanted]
    return collect_rule_findings(repo_root, files, settings)
