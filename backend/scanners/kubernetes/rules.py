"""Deterministic Kubernetes per-resource rule engine and rule registry.

Pure checks over the resource model. Cross-file relationship checks live in
`relationships.py`. Every rule maps to a stable ``K8Snnn`` identifier. No LLM.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from models.enums import Confidence, FindingCategory, Severity
from scanners.finding import RuleFinding
from scanners.kubernetes.model import K8sResource
from scanners.yaml_lines import line_of

SCANNER_NAME = "kubernetes-rules"

C = FindingCategory
S = Severity
CF = Confidence


@dataclass(frozen=True, slots=True)
class RuleSpec:
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    title: str
    recommendation: str


RULES: dict[str, RuleSpec] = {
    "K8S000": RuleSpec(C.CONFIGURATION, S.HIGH, CF.HIGH,
        "Invalid Kubernetes manifest", "Fix the manifest so it is valid YAML."),
    # Security
    "K8S001": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Privileged container", "Set securityContext.privileged: false."),
    "K8S002": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "hostNetwork enabled", "Remove hostNetwork: true."),
    "K8S003": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "hostPID enabled", "Remove hostPID: true."),
    "K8S004": RuleSpec(C.SECURITY, S.MEDIUM, CF.HIGH,
        "hostIPC enabled", "Remove hostIPC: true."),
    "K8S005": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "hostPath volume mounted", "Avoid hostPath; use PVCs or specific read-only mounts."),
    "K8S006": RuleSpec(C.SECURITY, S.MEDIUM, CF.HIGH,
        "allowPrivilegeEscalation not disabled",
        "Set securityContext.allowPrivilegeEscalation: false."),
    "K8S007": RuleSpec(C.SECURITY, S.MEDIUM, CF.MEDIUM,
        "runAsNonRoot not enforced", "Set securityContext.runAsNonRoot: true."),
    "K8S008": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Excessive Linux capabilities", "Drop ALL capabilities and add only what is required."),
    "K8S009": RuleSpec(C.SECURITY, S.LOW, CF.MEDIUM,
        "Insecure or missing seccomp profile",
        "Set securityContext.seccompProfile.type to RuntimeDefault."),
    "K8S010": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Unsafe sysctls", "Remove unsafe sysctls."),
    "K8S011": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Container runs as root (runAsUser 0)", "Run as a non-root UID."),
    # Reliability
    "K8S020": RuleSpec(C.RELIABILITY, S.LOW, CF.HIGH,
        "Missing readinessProbe", "Add a readinessProbe."),
    "K8S021": RuleSpec(C.RELIABILITY, S.LOW, CF.HIGH,
        "Missing livenessProbe", "Add a livenessProbe."),
    "K8S022": RuleSpec(C.RELIABILITY, S.INFO, CF.MEDIUM,
        "Missing startupProbe", "Consider a startupProbe for slow-starting apps."),
    "K8S023": RuleSpec(C.RELIABILITY, S.MEDIUM, CF.HIGH,
        "Missing resource requests", "Set resources.requests for cpu and memory."),
    "K8S024": RuleSpec(C.RELIABILITY, S.MEDIUM, CF.HIGH,
        "Missing resource limits", "Set resources.limits for cpu and memory."),
    "K8S025": RuleSpec(C.RELIABILITY, S.LOW, CF.MEDIUM,
        "Replicas not set", "Set spec.replicas explicitly (>= 2 for availability)."),
    "K8S026": RuleSpec(C.RELIABILITY, S.LOW, CF.MEDIUM,
        "No PodDisruptionBudget for a multi-replica workload",
        "Add a PodDisruptionBudget to protect availability during disruptions."),
    "K8S027": RuleSpec(C.RELIABILITY, S.INFO, CF.LOW,
        "No HorizontalPodAutoscaler for the workload",
        "Consider an HPA if the workload should scale with load."),
    # Image
    "K8S030": RuleSpec(C.SUPPLY_CHAIN, S.MEDIUM, CF.HIGH,
        "Image uses the 'latest' tag", "Pin the image to a specific version/digest."),
    "K8S031": RuleSpec(C.SUPPLY_CHAIN, S.MEDIUM, CF.HIGH,
        "Image is not pinned to a version", "Specify an explicit image tag or digest."),
    "K8S032": RuleSpec(C.SUPPLY_CHAIN, S.HIGH, CF.HIGH,
        "Vulnerable image", "Update the image to a patched version."),
    # Networking
    "K8S040": RuleSpec(C.SECURITY, S.MEDIUM, CF.HIGH,
        "Service exposed via NodePort", "Prefer ClusterIP + Ingress over NodePort."),
    "K8S041": RuleSpec(C.SECURITY, S.MEDIUM, CF.HIGH,
        "Service exposed via LoadBalancer",
        "Ensure a public LoadBalancer is intended and protected."),
    "K8S043": RuleSpec(C.SECURITY, S.MEDIUM, CF.MEDIUM,
        "Ingress without TLS", "Configure spec.tls for the Ingress."),
    "K8S044": RuleSpec(C.SECURITY, S.LOW, CF.MEDIUM,
        "Ingress uses a wildcard/catch-all host",
        "Restrict the Ingress to specific hostnames."),
    # RBAC
    "K8S050": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "RBAC rule uses wildcard apiGroups", "Grant specific API groups only."),
    "K8S051": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "RBAC rule uses wildcard verbs", "Grant specific verbs only."),
    "K8S052": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "RBAC rule uses wildcard resources", "Grant specific resources only."),
    "K8S053": RuleSpec(C.SECURITY, S.CRITICAL, CF.HIGH,
        "Binding grants cluster-admin", "Avoid binding cluster-admin; grant least privilege."),
    # Configuration
    "K8S060": RuleSpec(C.SECRETS, S.HIGH, CF.MEDIUM,
        "Secret data stored in a manifest",
        "Do not commit Secret values; use a secrets manager or sealed secrets."),
    "K8S061": RuleSpec(C.SECRETS, S.HIGH, CF.MEDIUM,
        "Credential in environment variable",
        "Use secretKeyRef/valueFrom instead of a literal value."),
    "K8S062": RuleSpec(C.CONFIGURATION, S.MEDIUM, CF.MEDIUM,
        "Secret-like data in a ConfigMap",
        "Store sensitive values in a Secret, not a ConfigMap."),
    # Relationships
    "K8S070": RuleSpec(C.RELIABILITY, S.MEDIUM, CF.HIGH,
        "Service selector matches no workload",
        "Fix the Service selector to match a workload's pod labels."),
    "K8S071": RuleSpec(C.RELIABILITY, S.HIGH, CF.HIGH,
        "Service targetPort does not match any container port",
        "Align the Service targetPort with a container's containerPort."),
    "K8S072": RuleSpec(C.RELIABILITY, S.HIGH, CF.HIGH,
        "Workload selector does not match its pod template labels",
        "Make spec.selector.matchLabels a subset of the pod template labels."),
    "K8S073": RuleSpec(C.CONFIGURATION, S.HIGH, CF.HIGH,
        "Ingress backend references a missing Service",
        "Reference an existing Service, or create the Service."),
    "K8S074": RuleSpec(C.CONFIGURATION, S.MEDIUM, CF.HIGH,
        "Ingress backend references a port the Service does not expose",
        "Use a port the Service actually exposes."),
    "K8S075": RuleSpec(C.RELIABILITY, S.LOW, CF.MEDIUM,
        "PodDisruptionBudget selector matches no workload",
        "Fix the PDB selector to match a workload's pod labels."),
    "K8S076": RuleSpec(C.CONFIGURATION, S.MEDIUM, CF.HIGH,
        "HPA references a missing scale target",
        "Point scaleTargetRef at an existing workload."),
}

_LONG_RUNNING = frozenset({"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Pod"})
_DANGEROUS_CAPS = {
    "ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_RAW",
    "SYS_RAWIO", "DAC_READ_SEARCH", "DAC_OVERRIDE", "SYS_BOOT", "SYS_TIME",
}
_SAFE_SYSCTLS = {
    "kernel.shm_rmid_forced", "net.ipv4.ip_local_port_range",
    "net.ipv4.tcp_syncookies", "net.ipv4.ping_group_range",
    "net.ipv4.ip_unprivileged_port_start",
}
_SECRET_KEY_RE = re.compile(
    r"(PASSWORD|PASSWD|SECRET|API[_-]?KEY|APIKEY|ACCESS[_-]?KEY|TOKEN|PRIVATE[_-]?KEY|PASSPHRASE)",
    re.IGNORECASE,
)
_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")


class Emitter:
    """Accumulates findings, filling static parts from ``RULES``."""

    def __init__(self) -> None:
        self.findings: list[RuleFinding] = []

    def add(
        self,
        rule_id: str,
        resource: K8sResource,
        *,
        description: str,
        line: int | None = None,
        evidence: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
    ) -> None:
        spec = RULES[rule_id]
        self.findings.append(
            RuleFinding(
                rule_id=rule_id,
                scanner=SCANNER_NAME,
                category=spec.category,
                severity=severity or spec.severity,
                confidence=confidence or spec.confidence,
                title=spec.title,
                description=description,
                recommendation=spec.recommendation,
                file_path=resource.file_path,
                line_number=line if line is not None else res_line(resource),
                evidence=evidence,
            )
        )


def res_line(resource: K8sResource) -> int | None:
    return line_of(resource.raw, "kind") or line_of(resource.raw, "apiVersion")


def make_syntax_finding(file_path: str, message: str, line: int | None) -> RuleFinding:
    spec = RULES["K8S000"]
    return RuleFinding(
        rule_id="K8S000",
        scanner=SCANNER_NAME,
        category=spec.category,
        severity=spec.severity,
        confidence=spec.confidence,
        title=spec.title,
        description=f"Manifest could not be parsed: {message}",
        recommendation=spec.recommendation,
        file_path=file_path,
        line_number=line,
        evidence=None,
    )


def parse_image(image: str) -> tuple[str, str | None, str | None]:
    ref = image
    digest = None
    tag = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    # A ':' after the last '/' is the tag (avoid registry host:port).
    last_segment = ref.rsplit("/", 1)[-1]
    if ":" in last_segment:
        name_tail, tag = last_segment.rsplit(":", 1)
        ref = ref[: len(ref) - len(last_segment)] + name_tail
    return ref, tag, digest


def analyze_resource(resource: K8sResource, emit: Emitter) -> None:
    """Run all per-resource checks applicable to a single resource."""
    kind = resource.kind
    if resource.is_pod_owner:
        _check_pod_security(resource, emit)
        _check_reliability(resource, emit)
        _check_images(resource, emit)
        _check_env_credentials(resource, emit)
    if kind == "Service":
        _check_service_networking(resource, emit)
    if kind == "Ingress":
        _check_ingress(resource, emit)
    if kind in {"Role", "ClusterRole"}:
        _check_rbac_rules(resource, emit)
    if kind in {"RoleBinding", "ClusterRoleBinding"}:
        _check_cluster_admin(resource, emit)
    if kind == "Secret":
        _check_secret(resource, emit)
    if kind == "ConfigMap":
        _check_configmap(resource, emit)


# --- security ---------------------------------------------------------------


def _sc(obj: dict) -> dict:
    sc = obj.get("securityContext")
    return sc if isinstance(sc, dict) else {}


def _check_pod_security(resource: K8sResource, emit: Emitter) -> None:
    pod_spec = resource.pod_spec()
    pod_sc = _sc(pod_spec)

    for flag, rule in (("hostNetwork", "K8S002"), ("hostPID", "K8S003"), ("hostIPC", "K8S004")):
        if pod_spec.get(flag) is True:
            emit.add(rule, resource, description=f"Pod sets {flag}: true.",
                     line=line_of(pod_spec, flag), evidence=f"{flag}: true")

    for volume in pod_spec.get("volumes", []) if isinstance(pod_spec.get("volumes"), list) else []:
        if isinstance(volume, dict) and "hostPath" in volume:
            path = str(_as_dict(volume.get("hostPath")).get("path", ""))
            emit.add("K8S005", resource, description=f"Pod mounts hostPath '{path}'.",
                     evidence=f"hostPath: {path}")

    sysctls = pod_sc.get("sysctls")
    if isinstance(sysctls, list):
        unsafe = [str(s.get("name")) for s in sysctls if isinstance(s, dict)
                  and str(s.get("name")) not in _SAFE_SYSCTLS]
        if unsafe:
            emit.add("K8S010", resource, description=f"Unsafe sysctls: {', '.join(unsafe)}.",
                     evidence=str(unsafe))

    pod_seccomp = _as_dict(pod_sc.get("seccompProfile")).get("type")

    for container in resource.containers():
        name = str(container.get("name", "?"))
        c_sc = _sc(container)
        cline = line_of(container, "name")

        if c_sc.get("privileged") is True:
            emit.add("K8S001", resource, description=f"Container '{name}' is privileged.",
                     line=cline, evidence="privileged: true")

        ape = c_sc.get("allowPrivilegeEscalation")
        if ape is not False:
            emit.add("K8S006", resource,
                     description=f"Container '{name}' does not disable privilege escalation.",
                     line=cline, evidence=f"allowPrivilegeEscalation: {ape}")

        run_as_non_root = c_sc.get("runAsNonRoot")
        if run_as_non_root is None:
            run_as_non_root = pod_sc.get("runAsNonRoot")
        if run_as_non_root is not True:
            emit.add("K8S007", resource,
                     description=f"Container '{name}' does not enforce runAsNonRoot.",
                     line=cline)

        run_as_user = c_sc.get("runAsUser", pod_sc.get("runAsUser"))
        if run_as_user == 0:
            emit.add("K8S011", resource,
                     description=f"Container '{name}' runs as root (runAsUser: 0).",
                     line=cline, evidence="runAsUser: 0")

        caps_add = _as_dict(c_sc.get("capabilities")).get("add")
        if isinstance(caps_add, list):
            dangerous = [str(c).upper() for c in caps_add if str(c).upper() in _DANGEROUS_CAPS]
            if dangerous:
                caps = ", ".join(dangerous)
                emit.add("K8S008", resource,
                         description=f"Container '{name}' adds capabilities {caps}.",
                         line=cline, evidence=str(dangerous))

        c_seccomp = _as_dict(c_sc.get("seccompProfile")).get("type", pod_seccomp)
        if c_seccomp is None or c_seccomp == "Unconfined":
            state = "unset" if c_seccomp is None else "Unconfined"
            emit.add("K8S009", resource,
                     description=f"Container '{name}' seccomp profile is {state}.",
                     line=cline)


# --- reliability ------------------------------------------------------------


def _has(container: dict, *keys: str) -> bool:
    resources = container.get("resources")
    if not isinstance(resources, dict):
        return False
    section = resources.get(keys[0])
    if not isinstance(section, dict):
        return False
    return any(section.get(k) for k in keys[1:])


def _check_reliability(resource: K8sResource, emit: Emitter) -> None:
    kind = resource.kind
    for container in resource.containers():
        name = str(container.get("name", "?"))
        cline = line_of(container, "name")
        if kind in _LONG_RUNNING:
            if "readinessProbe" not in container:
                emit.add("K8S020", resource,
                         description=f"Container '{name}' has no readinessProbe.", line=cline)
            if "livenessProbe" not in container:
                emit.add("K8S021", resource,
                         description=f"Container '{name}' has no livenessProbe.", line=cline)
            if "startupProbe" not in container:
                emit.add("K8S022", resource,
                         description=f"Container '{name}' has no startupProbe.", line=cline)
        if not _has(container, "requests", "cpu", "memory"):
            emit.add("K8S023", resource,
                     description=f"Container '{name}' sets no resource requests.", line=cline)
        if not _has(container, "limits", "cpu", "memory"):
            emit.add("K8S024", resource,
                     description=f"Container '{name}' sets no resource limits.", line=cline)

    if kind in {"Deployment", "StatefulSet"} and "replicas" not in resource.spec:
        emit.add("K8S025", resource, description=f"{kind} '{resource.name}' does not set replicas.")


# --- image ------------------------------------------------------------------


def _check_images(resource: K8sResource, emit: Emitter) -> None:
    for container in resource.containers():
        image = container.get("image")
        if not isinstance(image, str) or not image:
            continue
        cline = line_of(container, "image") or line_of(container, "name")
        _name, tag, digest = parse_image(image)
        if digest:
            continue
        if tag == "latest":
            emit.add("K8S030", resource, description=f"Image '{image}' uses the 'latest' tag.",
                     line=cline, evidence=f"image: {image}")
        elif tag is None:
            emit.add("K8S031", resource, description=f"Image '{image}' is not pinned.",
                     line=cline, evidence=f"image: {image}")


# --- env credentials --------------------------------------------------------


def _check_env_credentials(resource: K8sResource, emit: Emitter) -> None:
    for container in resource.containers():
        env = container.get("env")
        if not isinstance(env, list):
            continue
        for entry in env:
            if not isinstance(entry, dict) or "value" not in entry:
                continue
            key = str(entry.get("name", ""))
            value = str(entry.get("value", ""))
            if _AWS_ACCESS_KEY_RE.search(value):
                emit.add("K8S061", resource, description=f"Env '{key}' contains an AWS key.",
                         line=line_of(entry, "name"), evidence=f"{key}=<redacted>",
                         severity=Severity.CRITICAL)
            elif _SECRET_KEY_RE.search(key) and value and not value.startswith("$"):
                emit.add("K8S061", resource,
                         description=f"Env '{key}' has a hardcoded credential value.",
                         line=line_of(entry, "name"), evidence=f"{key}=<redacted>")


# --- networking -------------------------------------------------------------


def _check_service_networking(resource: K8sResource, emit: Emitter) -> None:
    svc_type = str(resource.spec.get("type", "ClusterIP"))
    if svc_type == "NodePort":
        emit.add("K8S040", resource, description=f"Service '{resource.name}' is a NodePort.",
                 line=line_of(resource.spec, "type"), evidence="type: NodePort")
    elif svc_type == "LoadBalancer":
        emit.add("K8S041", resource, description=f"Service '{resource.name}' is a LoadBalancer.",
                 line=line_of(resource.spec, "type"), evidence="type: LoadBalancer")


def _check_ingress(resource: K8sResource, emit: Emitter) -> None:
    spec = resource.spec
    if not spec.get("tls"):
        emit.add("K8S043", resource, description=f"Ingress '{resource.name}' has no TLS block.")
    for rule in spec.get("rules", []) if isinstance(spec.get("rules"), list) else []:
        if not isinstance(rule, dict):
            continue
        host = rule.get("host")
        if not host or "*" in str(host):
            emit.add("K8S044", resource,
                     description=f"Ingress '{resource.name}' uses a wildcard/catch-all host.",
                     evidence=f"host: {host}")


# --- RBAC -------------------------------------------------------------------


def _check_rbac_rules(resource: K8sResource, emit: Emitter) -> None:
    rules = resource.raw.get("rules")
    if not isinstance(rules, list):
        return
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if "*" in _as_list(rule.get("apiGroups")):
            emit.add("K8S050", resource, description=f"{resource.kind} grants all apiGroups (*).",
                     evidence="apiGroups: ['*']")
        if "*" in _as_list(rule.get("verbs")):
            emit.add("K8S051", resource, description=f"{resource.kind} grants all verbs (*).",
                     evidence="verbs: ['*']")
        if "*" in _as_list(rule.get("resources")):
            emit.add("K8S052", resource, description=f"{resource.kind} grants all resources (*).",
                     evidence="resources: ['*']")


def _check_cluster_admin(resource: K8sResource, emit: Emitter) -> None:
    role_ref = _as_dict(resource.raw.get("roleRef"))
    if str(role_ref.get("name")) == "cluster-admin":
        emit.add("K8S053", resource,
                 description=f"{resource.kind} '{resource.name}' binds cluster-admin.",
                 evidence="roleRef.name: cluster-admin")


# --- configuration ----------------------------------------------------------


def _check_secret(resource: K8sResource, emit: Emitter) -> None:
    data = resource.raw.get("data")
    string_data = resource.raw.get("stringData")
    keys = list(_as_dict(data).keys()) + list(_as_dict(string_data).keys())
    if keys:
        emit.add("K8S060", resource,
                 description=f"Secret '{resource.name}' embeds data keys: {', '.join(keys)}.",
                 evidence=f"keys: {keys}")


def _check_configmap(resource: K8sResource, emit: Emitter) -> None:
    data = _as_dict(resource.raw.get("data"))
    secretish = [k for k in data if _SECRET_KEY_RE.search(str(k))]
    if secretish:
        emit.add("K8S062", resource,
                 description=f"ConfigMap '{resource.name}' holds secret-like keys: "
                 f"{', '.join(secretish)}.",
                 evidence=f"keys: {secretish}")


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []
