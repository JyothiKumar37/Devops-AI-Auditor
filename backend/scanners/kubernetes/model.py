"""Kubernetes resource model.

Wraps a parsed manifest document with convenient, defensive accessors used by the
rule engine and the cross-file relationship analysis. All accessors tolerate
missing/oddly-typed fields so malformed manifests never crash a scan.
"""

from __future__ import annotations

from typing import Any

# Workloads that carry a pod template at spec.template.
TEMPLATE_WORKLOADS = frozenset(
    {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController"}
)
CRONJOB = "CronJob"
POD = "Pod"
# Any kind that ultimately owns a pod spec.
POD_OWNERS = TEMPLATE_WORKLOADS | {CRONJOB, POD}

SUPPORTED_KINDS = frozenset(
    {
        "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet",
        "ReplicationController", "Pod", "Service", "Ingress", "ConfigMap", "Secret",
        "ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding",
        "HorizontalPodAutoscaler", "PodDisruptionBudget", "PersistentVolumeClaim",
        "NetworkPolicy",
    }
)


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _str_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items()}


class K8sResource:
    """A single Kubernetes manifest document with convenience accessors."""

    def __init__(self, raw: dict, file_path: str, doc_index: int) -> None:
        self.raw = raw
        self.file_path = file_path
        self.doc_index = doc_index

    # -- identity ------------------------------------------------------------

    @property
    def api_version(self) -> str:
        return str(self.raw.get("apiVersion", ""))

    @property
    def kind(self) -> str:
        return str(self.raw.get("kind", ""))

    @property
    def metadata(self) -> dict:
        return _as_dict(self.raw.get("metadata"))

    @property
    def name(self) -> str:
        return str(self.metadata.get("name", ""))

    @property
    def namespace(self) -> str:
        return str(self.metadata.get("namespace", "default"))

    @property
    def labels(self) -> dict[str, str]:
        return _str_map(self.metadata.get("labels"))

    @property
    def spec(self) -> dict:
        return _as_dict(self.raw.get("spec"))

    # -- pod template --------------------------------------------------------

    @property
    def is_pod_owner(self) -> bool:
        return self.kind in POD_OWNERS

    def pod_template(self) -> dict | None:
        """Return the pod template dict (metadata + spec) for pod owners."""
        if self.kind in TEMPLATE_WORKLOADS:
            return _as_dict(self.spec.get("template")) or None
        if self.kind == CRONJOB:
            job = _as_dict(self.spec.get("jobTemplate"))
            return _as_dict(_as_dict(job.get("spec")).get("template")) or None
        if self.kind == POD:
            # A bare Pod acts as its own template.
            return self.raw
        return None

    def pod_spec(self) -> dict:
        template = self.pod_template()
        if template is None:
            return {}
        return _as_dict(template.get("spec"))

    def pod_labels(self) -> dict[str, str]:
        template = self.pod_template()
        if template is None:
            return {}
        return _str_map(_as_dict(template.get("metadata")).get("labels"))

    def containers(self) -> list[dict]:
        spec = self.pod_spec()
        containers = [c for c in _as_list(spec.get("containers")) if isinstance(c, dict)]
        init = [c for c in _as_list(spec.get("initContainers")) if isinstance(c, dict)]
        return containers + init

    # -- selectors -----------------------------------------------------------

    def workload_selector(self) -> dict[str, str] | None:
        """matchLabels of a workload selector, if present."""
        selector = _as_dict(self.spec.get("selector"))
        if not selector:
            return None
        return _str_map(selector.get("matchLabels", selector))

    def service_selector(self) -> dict[str, str]:
        return _str_map(self.spec.get("selector"))


class K8sModel:
    """All resources discovered across the repository, indexed for lookups."""

    def __init__(self, resources: list[K8sResource]) -> None:
        self.resources = resources

    def of_kind(self, *kinds: str) -> list[K8sResource]:
        wanted = set(kinds)
        return [r for r in self.resources if r.kind in wanted]

    @property
    def pod_owners(self) -> list[K8sResource]:
        return [r for r in self.resources if r.is_pod_owner]

    def workloads_in(self, namespace: str) -> list[K8sResource]:
        return [r for r in self.pod_owners if r.namespace == namespace]


def labels_match(selector: dict[str, str], labels: dict[str, str]) -> bool:
    """True if `labels` satisfies every entry of `selector` (non-empty selector)."""
    if not selector:
        return False
    return all(labels.get(k) == v for k, v in selector.items())
