"""Tests for the deterministic Docker Compose rule engine."""

from __future__ import annotations

from models.enums import Severity
from scanners.compose.scanner import DockerComposeScanner


def _rule_ids(text: str) -> set[str]:
    return {f.rule_id for f in DockerComposeScanner().analyze_text(text, "docker-compose.yml")}


def _findings(text: str):
    return DockerComposeScanner().analyze_text(text, "docker-compose.yml")


PROBLEMATIC = """\
services:
  db:
    image: postgres:latest
    privileged: true
    network_mode: host
    pid: host
    ipc: host
    cap_add:
      - SYS_ADMIN
    user: root
    environment:
      POSTGRES_PASSWORD: hunter2plaintext
      AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
      NODE_TLS_REJECT_UNAUTHORIZED: "0"
      DEBUG: "true"
    ports:
      - "0.0.0.0:5432:5432"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/host/etc:ro
      - ./data:/data
    depends_on:
      - cache
  web:
    image: nginx
"""


def test_problematic_compose_triggers_all_rules() -> None:
    ids = _rule_ids(PROBLEMATIC)
    expected = {
        "DCMP001", "DCMP002", "DCMP003", "DCMP004", "DCMP005", "DCMP006",
        "DCMP007", "DCMP008", "DCMP009", "DCMP010", "DCMP011", "DCMP012",
        "DCMP013", "DCMP014", "DCMP015", "DCMP016", "DCMP017", "DCMP018",
        "DCMP019", "DCMP021", "DCMP022", "DCMP023", "DCMP024", "DCMP025",
    }
    missing = expected - ids
    assert not missing, f"missing rules: {sorted(missing)}"


CLEAN = """\
services:
  web:
    image: nginx:1.25.3
    user: "1000"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 256M
    networks:
      - frontend
networks:
  frontend:
"""


def test_clean_compose_has_no_findings() -> None:
    assert _findings(CLEAN) == []


def test_privileged() -> None:
    assert "DCMP001" in _rule_ids("services:\n  a:\n    image: x:1\n    privileged: true\n")


def test_host_namespaces() -> None:
    text = "services:\n  a:\n    image: x:1\n    network_mode: host\n    pid: host\n    ipc: host\n"
    ids = _rule_ids(text)
    assert {"DCMP002", "DCMP003", "DCMP004"} <= ids


def test_excessive_capabilities() -> None:
    assert "DCMP005" in _rule_ids("services:\n  a:\n    image: x:1\n    cap_add: [NET_ADMIN]\n")


def test_root_user_vs_missing_user() -> None:
    assert "DCMP006" in _rule_ids("services:\n  a:\n    image: x:1\n    user: root\n")
    assert "DCMP007" in _rule_ids("services:\n  a:\n    image: x:1\n")


def test_secret_and_apikey_severities() -> None:
    findings = _findings(
        "services:\n  a:\n    image: x:1\n    user: '1'\n"
        "    environment:\n      DB_PASSWORD: literalsecret\n      API_KEY: abcd1234\n"
    )
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["DCMP011"].severity == Severity.HIGH
    assert by_rule["DCMP012"].severity == Severity.CRITICAL
    # Secret values must never appear in evidence.
    assert "literalsecret" not in (by_rule["DCMP011"].evidence or "")


def test_secret_env_variable_reference_ignored() -> None:
    text = (
        "services:\n  a:\n    image: x:1\n    user: '1'\n"
        "    environment:\n      DB_PASSWORD: ${DB_PASSWORD}\n"
    )
    assert "DCMP011" not in _rule_ids(text)


def _one_service(body: str) -> str:
    """Wrap an indented service body in a minimal single-service compose file."""
    return "services:\n  a:\n    image: x:1\n" + body


def test_exposed_database_port() -> None:
    assert "DCMP013" in _rule_ids(_one_service('    ports:\n      - "5432:5432"\n'))


def test_non_database_port_is_clean() -> None:
    assert "DCMP013" not in _rule_ids(_one_service('    ports:\n      - "8080:8080"\n'))


def test_bind_all_interfaces() -> None:
    assert "DCMP014" in _rule_ids(_one_service('    ports:\n      - "0.0.0.0:8080:80"\n'))


def test_latest_and_unpinned() -> None:
    assert "DCMP015" in _rule_ids("services:\n  a:\n    image: redis:latest\n")
    assert "DCMP016" in _rule_ids("services:\n  a:\n    image: redis\n")


def test_docker_socket_mount_is_critical() -> None:
    findings = _findings(
        "services:\n  a:\n    image: x:1\n    user: '1'\n"
        "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
    )
    sock = next(f for f in findings if f.rule_id == "DCMP017")
    assert sock.severity == Severity.CRITICAL


def test_sensitive_and_general_host_mounts() -> None:
    assert "DCMP018" in _rule_ids(_one_service("    volumes:\n      - /etc:/etc\n"))
    assert "DCMP019" in _rule_ids(_one_service("    volumes:\n      - ./app:/app\n"))


def test_named_volume_is_not_a_host_mount() -> None:
    text = _one_service("    volumes:\n      - data:/var/lib\n") + "volumes:\n  data:\n"
    ids = _rule_ids(text)
    assert "DCMP018" not in ids
    assert "DCMP019" not in ids


def test_depends_on_condition_and_undefined() -> None:
    short = "services:\n  a:\n    image: x:1\n    depends_on:\n      - b\n  b:\n    image: y:1\n"
    assert "DCMP021" in _rule_ids(short)

    undefined = "services:\n  a:\n    image: x:1\n    depends_on:\n      - ghost\n"
    assert "DCMP022" in _rule_ids(undefined)


def test_depends_on_with_condition_is_clean_for_dcmp021() -> None:
    text = (
        "services:\n  a:\n    image: x:1\n    user: '1'\n"
        "    depends_on:\n      b:\n        condition: service_healthy\n"
        "  b:\n    image: y:1\n    user: '1'\n"
    )
    assert "DCMP021" not in _rule_ids(text)


def test_syntax_error_produces_dcmp000() -> None:
    findings = _findings("services:\n  a:\n  - broken: [unclosed\n")
    assert findings and findings[0].rule_id == "DCMP000"


def test_non_compose_yaml_produces_dcmp000() -> None:
    findings = _findings("just: a map\nwithout: services\n")
    assert findings and findings[0].rule_id == "DCMP000"


def test_findings_carry_full_schema() -> None:
    finding = next(f for f in _findings(PROBLEMATIC) if f.rule_id == "DCMP001")
    assert finding.scanner == "compose-rules"
    assert finding.title and finding.description and finding.recommendation
    assert finding.line_number is not None
    assert finding.category is not None and finding.confidence is not None
