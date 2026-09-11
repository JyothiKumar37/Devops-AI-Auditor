"""Tests for the Kubernetes resource model and multi-document parsing."""

from __future__ import annotations

from scanners.kubernetes.model import K8sResource
from scanners.yaml_lines import load_documents

DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
        tier: frontend
    spec:
      containers:
        - name: web
          image: nginx:1.25
          ports:
            - containerPort: 8080
"""

CRONJOB = """\
apiVersion: batch/v1
kind: CronJob
metadata:
  name: report
spec:
  schedule: "0 0 * * *"
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            app: report
        spec:
          containers:
            - name: report
              image: report:1.0
"""


def _resource(text: str) -> K8sResource:
    docs = load_documents(text)
    return K8sResource(docs[0], "manifest.yaml", 0)


def test_basic_identity() -> None:
    res = _resource(DEPLOYMENT)
    assert res.kind == "Deployment"
    assert res.name == "web"
    assert res.namespace == "prod"


def test_pod_labels_and_containers() -> None:
    res = _resource(DEPLOYMENT)
    assert res.pod_labels() == {"app": "web", "tier": "frontend"}
    containers = res.containers()
    assert len(containers) == 1
    assert containers[0]["image"] == "nginx:1.25"


def test_workload_selector() -> None:
    assert _resource(DEPLOYMENT).workload_selector() == {"app": "web"}


def test_cronjob_pod_template() -> None:
    res = _resource(CRONJOB)
    assert res.is_pod_owner
    assert res.pod_labels() == {"app": "report"}
    assert res.containers()[0]["image"] == "report:1.0"


def test_multi_document_and_default_namespace() -> None:
    text = DEPLOYMENT + "---\n" + "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\n"
    docs = load_documents(text)
    assert len(docs) == 2
    svc = K8sResource(docs[1], "m.yaml", 1)
    assert svc.kind == "Service"
    assert svc.namespace == "default"
