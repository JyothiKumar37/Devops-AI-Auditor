"""Tests for cross-file Kubernetes relationship analysis (the core of Stage 6)."""

from __future__ import annotations

from scanners.kubernetes import KubernetesScanner

DEPLOYMENT_8080 = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: nginx:1.25
          ports:
            - containerPort: 8080
"""


def _ids(*manifests: str) -> set[str]:
    files = [(f"m{i}.yaml", m) for i, m in enumerate(manifests)]
    return {f.rule_id for f in KubernetesScanner().analyze_manifests(files)}


def test_service_targetport_mismatch_is_reported() -> None:
    # Deployment exposes 8080 but Service targets 80 -> the canonical example.
    service_80 = """\
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: default
spec:
  selector:
    app: web
  ports:
    - port: 80
      targetPort: 80
"""
    assert "K8S071" in _ids(DEPLOYMENT_8080, service_80)


def test_matching_targetport_is_clean() -> None:
    service_8080 = """\
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: default
spec:
  selector:
    app: web
  ports:
    - port: 80
      targetPort: 8080
"""
    assert "K8S071" not in _ids(DEPLOYMENT_8080, service_8080)


def test_service_selects_no_workload() -> None:
    service_wrong_selector = """\
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: default
spec:
  selector:
    app: nonexistent
  ports:
    - port: 80
      targetPort: 8080
"""
    ids = _ids(DEPLOYMENT_8080, service_wrong_selector)
    assert "K8S070" in ids
    assert "K8S071" not in ids  # cannot assert a port mismatch when nothing is selected


def test_self_selector_mismatch() -> None:
    broken = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: different
    spec:
      containers:
        - name: web
          image: nginx:1.25
"""
    assert "K8S072" in _ids(broken)


def test_ingress_missing_service_and_bad_port() -> None:
    service = """\
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: default
spec:
  selector:
    app: web
  ports:
    - port: 80
      targetPort: 8080
"""
    ingress_missing = """\
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: i
  namespace: default
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: ghost
                port:
                  number: 80
"""
    assert "K8S073" in _ids(DEPLOYMENT_8080, service, ingress_missing)

    ingress_bad_port = ingress_missing.replace("name: ghost", "name: web").replace(
        "number: 80", "number: 9999"
    )
    ids = _ids(DEPLOYMENT_8080, service, ingress_bad_port)
    assert "K8S074" in ids
    assert "K8S073" not in ids


def test_pdb_selects_nothing() -> None:
    pdb = """\
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: web
  namespace: default
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: ghost
"""
    assert "K8S075" in _ids(DEPLOYMENT_8080, pdb)


def test_hpa_missing_target() -> None:
    hpa = """\
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web
  namespace: default
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ghost
  minReplicas: 1
  maxReplicas: 5
"""
    assert "K8S076" in _ids(DEPLOYMENT_8080, hpa)


CLEAN = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
  labels:
    app: web
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: web
          image: nginx:1.25.3
          ports:
            - containerPort: 8080
          readinessProbe:
            httpGet:
              path: /
              port: 8080
          livenessProbe:
            httpGet:
              path: /
              port: 8080
          startupProbe:
            httpGet:
              path: /
              port: 8080
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 1000
            seccompProfile:
              type: RuntimeDefault
            capabilities:
              drop: [ALL]
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: default
spec:
  selector:
    app: web
  ports:
    - port: 80
      targetPort: 8080
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: web
  namespace: default
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: web
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web
  namespace: default
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web
  minReplicas: 2
  maxReplicas: 5
"""


def test_clean_manifests_have_no_findings() -> None:
    findings = KubernetesScanner().analyze_manifests([("clean.yaml", CLEAN)])
    assert findings == [], [f"{f.rule_id}:{f.title}" for f in findings]
