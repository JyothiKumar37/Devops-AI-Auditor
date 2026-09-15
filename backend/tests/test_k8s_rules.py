"""Tests for the deterministic per-resource Kubernetes rules."""

from __future__ import annotations

from models.enums import Severity
from scanners.kubernetes import KubernetesScanner


def _ids(text: str) -> set[str]:
    findings = KubernetesScanner().analyze_manifests([("m.yaml", text)])
    return {f.rule_id for f in findings}


def _findings(text: str):
    return KubernetesScanner().analyze_manifests([("m.yaml", text)])


INSECURE_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: bad
  labels:
    app: bad
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  volumes:
    - name: host
      hostPath:
        path: /
  containers:
    - name: c
      image: busybox:latest
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        runAsUser: 0
        capabilities:
          add: [SYS_ADMIN]
      env:
        - name: DB_PASSWORD
          value: literalsecret
"""


def test_insecure_pod_security_rules() -> None:
    ids = _ids(INSECURE_POD)
    for expected in {
        "K8S001", "K8S002", "K8S003", "K8S004", "K8S005",
        "K8S006", "K8S008", "K8S011", "K8S030", "K8S061",
    }:
        assert expected in ids, f"missing {expected}: {sorted(ids)}"


def test_env_credential_is_redacted() -> None:
    finding = next(f for f in _findings(INSECURE_POD) if f.rule_id == "K8S061")
    assert "literalsecret" not in (finding.evidence or "")


SAFE_ENV_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: cfg
spec:
  containers:
    - name: c
      image: app:1.2.3
      env:
        - name: SESSION_TOKEN_TTL
          value: "3600"
        - name: API_TOKEN_TIMEOUT
          value: "30s"
        - name: AUTH_TOKEN_MODE
          value: STRICT_MODE
        - name: REAL_API_TOKEN
          value: s3cr3tL00kingValue
"""


def test_env_config_values_are_not_flagged_as_credentials() -> None:
    # Duration/TTL/number/symbolic env values must not be treated as credentials;
    # only the genuine literal secret should raise K8S061.
    creds = [f for f in _findings(SAFE_ENV_POD) if f.rule_id == "K8S061"]
    assert len(creds) == 1
    assert "REAL_API_TOKEN" in creds[0].description


def test_missing_probes_and_resources() -> None:
    text = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\n"
        "spec:\n  selector:\n    matchLabels:\n      app: d\n"
        "  template:\n    metadata:\n      labels:\n        app: d\n"
        "    spec:\n      containers:\n        - name: c\n          image: nginx:1.25\n"
    )
    ids = _ids(text)
    assert {"K8S020", "K8S021", "K8S022", "K8S023", "K8S024", "K8S025"} <= ids


def test_unpinned_image() -> None:
    text = (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
        "spec:\n  containers:\n    - name: c\n      image: nginx\n"
    )
    assert "K8S031" in _ids(text)


def test_service_nodeport_and_loadbalancer() -> None:
    nodeport = (
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: s\n"
        "spec:\n  type: NodePort\n  selector:\n    app: x\n  ports:\n    - port: 80\n"
    )
    assert "K8S040" in _ids(nodeport)
    lb = nodeport.replace("NodePort", "LoadBalancer")
    assert "K8S041" in _ids(lb)


def test_ingress_without_tls_and_wildcard() -> None:
    text = (
        "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: i\n"
        "spec:\n  rules:\n    - host: '*.example.com'\n      http:\n        paths: []\n"
    )
    ids = _ids(text)
    assert "K8S043" in ids
    assert "K8S044" in ids


def test_rbac_wildcards_and_cluster_admin() -> None:
    role = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: r\n"
        "rules:\n  - apiGroups: ['*']\n    resources: ['*']\n    verbs: ['*']\n"
    )
    assert {"K8S050", "K8S051", "K8S052"} <= _ids(role)

    binding = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: b\n"
        "roleRef:\n  kind: ClusterRole\n  name: cluster-admin\n"
        "subjects:\n  - kind: ServiceAccount\n    name: default\n"
    )
    cluster_admin = next(f for f in _findings(binding) if f.rule_id == "K8S053")
    assert cluster_admin.severity == Severity.CRITICAL


def test_secret_and_configmap_misuse() -> None:
    secret = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ndata:\n  password: aGVsbG8=\n"
    assert "K8S060" in _ids(secret)
    configmap = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\ndata:\n  API_KEY: abc\n"
    assert "K8S062" in _ids(configmap)


def test_invalid_manifest_yields_k8s000() -> None:
    findings = KubernetesScanner().analyze_manifests([("bad.yaml", "kind: [unclosed\n")])
    assert findings and findings[0].rule_id == "K8S000"
