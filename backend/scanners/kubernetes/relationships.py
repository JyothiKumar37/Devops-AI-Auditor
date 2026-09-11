"""Cross-file Kubernetes relationship analysis.

This is the core value of analysing manifests *together*: it follows the chain

    workload selector -> pod labels -> Service selector -> Service targetPort
    -> container ports -> Ingress backend -> Service port

and reports mismatches that are invisible when each file is viewed in isolation.
Every finding is backed by concrete evidence in the manifests; when the evidence
is insufficient (e.g. no container ports are declared at all) no finding is
emitted, to avoid false positives.
"""

from __future__ import annotations

from typing import Any

from scanners.kubernetes.model import K8sModel, K8sResource, labels_match
from scanners.kubernetes.rules import Emitter, res_line


def analyze_relationships(model: K8sModel, emit: Emitter) -> None:
    _check_self_selectors(model, emit)
    _check_services(model, emit)
    _check_ingresses(model, emit)
    _check_pdbs(model, emit)
    _check_hpas(model, emit)


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _container_ports(workloads: list[K8sResource]) -> tuple[set[int], set[str], bool]:
    """Collect declared container ports across workloads.

    Returns (numeric ports, named ports, any_declared).
    """
    numbers: set[int] = set()
    names: set[str] = set()
    any_declared = False
    for workload in workloads:
        for container in workload.containers():
            ports = container.get("ports")
            if not isinstance(ports, list):
                continue
            for port in ports:
                if not isinstance(port, dict):
                    continue
                container_port = port.get("containerPort")
                if isinstance(container_port, int):
                    numbers.add(container_port)
                    any_declared = True
                if port.get("name"):
                    names.add(str(port.get("name")))
                    any_declared = True
    return numbers, names, any_declared


def _check_self_selectors(model: K8sModel, emit: Emitter) -> None:
    for workload in model.pod_owners:
        selector = workload.workload_selector()
        if not selector:
            continue
        if not labels_match(selector, workload.pod_labels()):
            emit.add(
                "K8S072",
                workload,
                description=f"{workload.kind} '{workload.name}' selector {selector} does not "
                f"match its pod template labels {workload.pod_labels()}.",
                evidence=f"selector={selector} labels={workload.pod_labels()}",
            )


def _check_services(model: K8sModel, emit: Emitter) -> None:
    for service in model.of_kind("Service"):
        selector = service.service_selector()
        if not selector:
            continue  # headless/externally-managed service; nothing to correlate
        matched = [
            w for w in model.workloads_in(service.namespace)
            if labels_match(selector, w.pod_labels())
        ]
        if not matched:
            emit.add(
                "K8S070",
                service,
                description=f"Service '{service.name}' selector {selector} matches no workload "
                f"in namespace '{service.namespace}'.",
                evidence=f"selector={selector}",
            )
            continue

        numbers, names, any_declared = _container_ports(matched)
        if not any_declared:
            continue  # no container ports declared -> cannot assert a mismatch

        for port in _as_list(service.spec.get("ports")):
            if not isinstance(port, dict):
                continue
            target = port.get("targetPort", port.get("port"))
            if target is None:
                continue
            if isinstance(target, int) or str(target).isdigit():
                if int(target) not in numbers:
                    emit.add(
                        "K8S071",
                        service,
                        description=f"Service '{service.name}' targetPort {target} does not match "
                        f"any container port {sorted(numbers)} of the selected workload.",
                        evidence=f"targetPort={target}, containerPorts={sorted(numbers)}",
                    )
            elif str(target) not in names:
                emit.add(
                    "K8S071",
                    service,
                    description=f"Service '{service.name}' named targetPort '{target}' is not "
                    f"exposed by the selected workload (named ports: {sorted(names)}).",
                    evidence=f"targetPort={target}, namedPorts={sorted(names)}",
                )


def _iter_ingress_backends(ingress: K8sResource) -> list[tuple[str, Any]]:
    """Return (service_name, port) pairs referenced by an Ingress (v1 + legacy)."""
    backends: list[tuple[str, Any]] = []
    spec = ingress.spec

    def add_backend(backend: dict) -> None:
        service = _as_dict(backend.get("service"))
        if service:  # networking.k8s.io/v1
            port = _as_dict(service.get("port"))
            backends.append((str(service.get("name", "")), port.get("number", port.get("name"))))
        elif backend.get("serviceName"):  # legacy extensions/v1beta1
            backends.append((str(backend.get("serviceName")), backend.get("servicePort")))

    if isinstance(spec.get("defaultBackend"), dict):
        add_backend(spec["defaultBackend"])
    for rule in _as_list(spec.get("rules")):
        http = _as_dict(_as_dict(rule).get("http"))
        for path in _as_list(http.get("paths")):
            backend = _as_dict(_as_dict(path).get("backend"))
            if backend:
                add_backend(backend)
    return backends


def _check_ingresses(model: K8sModel, emit: Emitter) -> None:
    services = {(s.namespace, s.name): s for s in model.of_kind("Service")}
    for ingress in model.of_kind("Ingress"):
        for service_name, port in _iter_ingress_backends(ingress):
            if not service_name:
                continue
            service = services.get((ingress.namespace, service_name))
            if service is None:
                emit.add(
                    "K8S073",
                    ingress,
                    description=f"Ingress '{ingress.name}' references Service '{service_name}', "
                    f"which does not exist in namespace '{ingress.namespace}'.",
                    evidence=f"service={service_name}",
                )
                continue
            if port is None:
                continue
            svc_numbers = {p.get("port") for p in _as_list(service.spec.get("ports"))
                           if isinstance(p, dict)}
            svc_names = {p.get("name") for p in _as_list(service.spec.get("ports"))
                         if isinstance(p, dict)}
            ok = (
                int(port) in svc_numbers if str(port).isdigit() else str(port) in svc_names
            )
            if not ok:
                emit.add(
                    "K8S074",
                    ingress,
                    description=f"Ingress '{ingress.name}' targets port '{port}' on Service "
                    f"'{service_name}', which does not expose it.",
                    evidence=f"port={port}",
                )


def _pdb_selector(pdb: K8sResource) -> dict[str, str]:
    selector = _as_dict(pdb.spec.get("selector"))
    match_labels = selector.get("matchLabels", {})
    if not isinstance(match_labels, dict):
        return {}
    return {str(k): str(v) for k, v in match_labels.items()}


def _check_pdbs(model: K8sModel, emit: Emitter) -> None:
    pdbs = model.of_kind("PodDisruptionBudget")
    for pdb in pdbs:
        selector = _pdb_selector(pdb)
        if not selector:
            continue
        matched = [w for w in model.workloads_in(pdb.namespace)
                   if labels_match(selector, w.pod_labels())]
        if not matched:
            emit.add(
                "K8S075",
                pdb,
                description=f"PodDisruptionBudget '{pdb.name}' selector {selector} matches no "
                f"workload in namespace '{pdb.namespace}'.",
                evidence=f"selector={selector}",
            )

    # Missing PDB for multi-replica workloads.
    for workload in model.of_kind("Deployment", "StatefulSet"):
        replicas = workload.spec.get("replicas")
        if not isinstance(replicas, int) or replicas < 2:
            continue
        labels = workload.pod_labels()
        covered = any(
            labels_match(_pdb_selector(pdb), labels)
            for pdb in pdbs
            if pdb.namespace == workload.namespace and _pdb_selector(pdb)
        )
        if not covered:
            emit.add(
                "K8S026",
                workload,
                description=f"{workload.kind} '{workload.name}' has {replicas} replicas but no "
                f"PodDisruptionBudget covers it.",
                line=res_line(workload),
            )


def _check_hpas(model: K8sModel, emit: Emitter) -> None:
    hpas = model.of_kind("HorizontalPodAutoscaler")
    workloads_by_ref = {
        (w.namespace, w.kind, w.name): w for w in model.pod_owners
    }
    for hpa in hpas:
        ref = _as_dict(hpa.spec.get("scaleTargetRef"))
        target_kind = str(ref.get("kind", ""))
        target_name = str(ref.get("name", ""))
        if target_name and (hpa.namespace, target_kind, target_name) not in workloads_by_ref:
            emit.add(
                "K8S076",
                hpa,
                description=f"HPA '{hpa.name}' targets {target_kind}/{target_name}, which does "
                f"not exist in namespace '{hpa.namespace}'.",
                evidence=f"scaleTargetRef={target_kind}/{target_name}",
            )

    # Informational: Deployments without an HPA.
    hpa_targets = {
        (h.namespace, str(_as_dict(h.spec.get("scaleTargetRef")).get("name")))
        for h in hpas
    }
    for deployment in model.of_kind("Deployment"):
        if (deployment.namespace, deployment.name) not in hpa_targets:
            emit.add(
                "K8S027",
                deployment,
                description=f"Deployment '{deployment.name}' has no HorizontalPodAutoscaler.",
                line=res_line(deployment),
            )
