"""Cross-stack entity extraction for correlation.

Builds a compact, JSON-serialisable index of the entities that matter for
cross-file correlation (Terraform databases/EKS, Kubernetes workloads/services/
secrets/namespaces/images, CI/CD deploy targets). It is produced during
ingestion while the workspace still exists and persisted on the scan, so the
correlation engine can reason across stacks after cleanup.

Extraction is read-only and deterministic; it reuses the existing parsers.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from core.logging import get_logger
from scanners.kubernetes.model import K8sResource
from scanners.terraform.parser import TerraformSyntaxError, parse_hcl
from scanners.yaml_lines import YamlSyntaxError, load_documents

logger = get_logger(__name__)

_DB_ENGINES = ("mysql", "postgres", "postgresql", "aurora", "mariadb", "oracle", "sqlserver")
_DB_HOST_KEYS = {
    "DATABASE_URL", "DB_HOST", "DB_HOSTNAME", "DB_URL", "POSTGRES_HOST", "MYSQL_HOST",
    "PGHOST", "MONGODB_URI", "MONGO_URL", "REDIS_HOST", "DB_ENDPOINT",
}
_RDS_HOST_RE = re.compile(r"[a-z0-9.-]+\.rds\.amazonaws\.com", re.IGNORECASE)
_NS_YAML_RE = re.compile(r"(?m)^\s*namespace:\s*[\"']?([A-Za-z0-9_.-]+)")
_NS_KUBECTL_RE = re.compile(r"(?:-n|--namespace[=\s])\s*[\"']?([A-Za-z0-9_.-]+)")
_TEMPLATED_RE = re.compile(r"[$${{]")


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() in {"true", "1"})


def empty_index() -> dict[str, Any]:
    return {
        "tf_databases": [],
        "eks_clusters": [],
        "k8s_workloads": [],
        "k8s_services": [],
        "k8s_defined_secrets": [],
        "k8s_defined_configmaps": [],
        "k8s_namespaces": [],
        "cicd": {
            "deploy_namespaces": [],
            "has_kubectl": False,
            "has_terraform_apply": False,
            "has_image_build": False,
            "files": [],
        },
    }


class CorrelationExtractor:
    """Extracts the cross-stack entity index from an extracted repository."""

    def extract(self, repo_root: Path, files: list[tuple[str, str]]) -> dict[str, Any]:
        """Build the index from (relative_path, detected_type) entries."""
        index = empty_index()
        namespaces: set[str] = set()

        for rel, detected_type in files:
            text = self._read(repo_root / rel)
            if text is None:
                continue
            if detected_type == "terraform":
                self._terraform(rel, text, index)
            elif detected_type == "kubernetes":
                self._kubernetes(rel, text, index, namespaces)
            elif detected_type in {"github_actions", "gitlab_ci", "jenkins"}:
                self._cicd(rel, text, index)

        index["k8s_namespaces"] = sorted(namespaces)
        index["cicd"]["deploy_namespaces"] = sorted(set(index["cicd"]["deploy_namespaces"]))
        return index

    @staticmethod
    def _read(path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None

    # -- terraform -----------------------------------------------------------

    def _terraform(self, rel: str, text: str, index: dict[str, Any]) -> None:
        try:
            parsed = parse_hcl(text)
        except TerraformSyntaxError:
            return
        for entry in _as_list(parsed.get("resource")):
            for rtype, named in entry.items():
                if not isinstance(named, dict):
                    continue
                for name, body in named.items():
                    body = _as_dict(body)
                    address = f"{rtype}.{name}"
                    if rtype in {"aws_db_instance", "aws_rds_cluster"}:
                        index["tf_databases"].append({
                            "file": rel,
                            "address": address,
                            "engine": str(body.get("engine", "")),
                            "publicly_accessible": _truthy(body.get("publicly_accessible")),
                        })
                    elif rtype == "aws_eks_cluster":
                        index["eks_clusters"].append({"file": rel, "name": name})

    # -- kubernetes ----------------------------------------------------------

    def _kubernetes(
        self, rel: str, text: str, index: dict[str, Any], namespaces: set[str]
    ) -> None:
        try:
            documents = load_documents(text)
        except YamlSyntaxError:
            return
        for doc in documents:
            if not isinstance(doc, dict) or not doc.get("kind"):
                continue
            resource = K8sResource(doc, rel, 0)
            kind = resource.kind
            ns = resource.namespace
            namespaces.add(ns)

            if kind == "Service":
                index["k8s_services"].append({"file": rel, "name": resource.name, "namespace": ns})
            elif kind == "Secret":
                index["k8s_defined_secrets"].append(
                    {"file": rel, "name": resource.name, "namespace": ns}
                )
            elif kind == "ConfigMap":
                index["k8s_defined_configmaps"].append(
                    {"file": rel, "name": resource.name, "namespace": ns}
                )
            elif resource.is_pod_owner:
                index["k8s_workloads"].append(self._workload(resource, rel, ns))

    def _workload(self, resource: K8sResource, rel: str, ns: str) -> dict[str, Any]:
        images: list[str] = []
        db_hosts: list[str] = []
        secret_refs: set[str] = set()
        configmap_refs: set[str] = set()

        for container in resource.containers():
            image = container.get("image")
            if isinstance(image, str):
                images.append(image)
            for env in _as_list(container.get("env")):
                if not isinstance(env, dict):
                    continue
                key = str(env.get("name", ""))
                value = env.get("value")
                if isinstance(value, str) and (
                    key.upper() in _DB_HOST_KEYS or _RDS_HOST_RE.search(value)
                ):
                    db_hosts.append(value)
                value_from = _as_dict(env.get("valueFrom"))
                secret_refs.update(self._ref(value_from, "secretKeyRef"))
                configmap_refs.update(self._ref(value_from, "configMapKeyRef"))
            for env_from in _as_list(container.get("envFrom")):
                if isinstance(env_from, dict):
                    secret_refs.update(self._ref(env_from, "secretRef"))
                    configmap_refs.update(self._ref(env_from, "configMapRef"))

        for volume in _as_list(resource.pod_spec().get("volumes")):
            if not isinstance(volume, dict):
                continue
            if isinstance(volume.get("secret"), dict):
                name = volume["secret"].get("secretName")
                if name:
                    secret_refs.add(str(name))
            if isinstance(volume.get("configMap"), dict):
                name = volume["configMap"].get("name")
                if name:
                    configmap_refs.add(str(name))

        return {
            "file": rel,
            "name": resource.name,
            "namespace": ns,
            "images": images,
            "db_hosts": db_hosts,
            "secret_refs": sorted(secret_refs),
            "configmap_refs": sorted(configmap_refs),
        }

    @staticmethod
    def _ref(container: dict, key: str) -> set[str]:
        ref = _as_dict(container.get(key))
        name = ref.get("name")
        return {str(name)} if name else set()

    # -- ci/cd ---------------------------------------------------------------

    def _cicd(self, rel: str, text: str, index: dict[str, Any]) -> None:
        cicd = index["cicd"]
        cicd["files"].append(rel)
        if "kubectl" in text:
            cicd["has_kubectl"] = True
        if re.search(r"\bterraform\s+(apply|plan|init)\b", text):
            cicd["has_terraform_apply"] = True
        if re.search(r"docker\s+build|build-push-action|buildx|kaniko|docker\s+buildx", text):
            cicd["has_image_build"] = True
        for match in list(_NS_YAML_RE.finditer(text)) + list(_NS_KUBECTL_RE.finditer(text)):
            ns = match.group(1)
            if not _TEMPLATED_RE.search(ns) and ns not in {"name", "true", "false"}:
                cicd["deploy_namespaces"].append(ns)
