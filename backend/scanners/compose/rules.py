"""Deterministic Docker Compose rule engine.

Pure functions over the parsed Compose model. Every rule maps to a stable
``DCMPnnn`` identifier. No randomness, network, or LLM.

Covered checks (the 20 required by the specification):

    DCMP001 privileged container        DCMP013 exposed database port
    DCMP002 host network mode           DCMP014 0.0.0.0 binding
    DCMP003 host PID namespace          DCMP015 latest image tag
    DCMP004 host IPC namespace          DCMP016 unpinned image
    DCMP005 excessive capabilities      DCMP017 docker socket mount
    DCMP006 runs as root                DCMP018 sensitive host mount
    DCMP007 no user specified           DCMP019 host filesystem mount
    DCMP008 missing healthcheck         DCMP021 depends_on without condition
    DCMP009 missing restart policy      DCMP022 depends_on undefined service
    DCMP010 missing resource limits     DCMP023 missing explicit networks
    DCMP011 hardcoded password/secret   DCMP024 insecure env (TLS/SSL off)
    DCMP012 hardcoded API key           DCMP025 debug enabled

DCMP000 is reserved for Compose syntax/structure errors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from models.enums import Confidence, FindingCategory, Severity
from scanners.compose.parser import line_of
from scanners.finding import RuleFinding

SCANNER_NAME = "compose-rules"


@dataclass(frozen=True, slots=True)
class RuleSpec:
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    title: str
    recommendation: str


C = FindingCategory
S = Severity
CF = Confidence

RULES: dict[str, RuleSpec] = {
    "DCMP000": RuleSpec(C.CONFIGURATION, S.HIGH, CF.HIGH,
        "Invalid Docker Compose file",
        "Ensure the file is valid YAML with a 'services' mapping."),
    "DCMP001": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Privileged container",
        "Remove 'privileged: true'; grant only specific capabilities if needed."),
    "DCMP002": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Host network mode",
        "Avoid 'network_mode: host'; use bridge networks and publish only needed ports."),
    "DCMP003": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Host PID namespace shared",
        "Remove 'pid: host' to preserve process isolation."),
    "DCMP004": RuleSpec(C.SECURITY, S.MEDIUM, CF.HIGH,
        "Host IPC namespace shared",
        "Remove 'ipc: host' unless strictly required."),
    "DCMP005": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Excessive Linux capabilities",
        "Drop all capabilities and add back only the minimum required."),
    "DCMP006": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Service runs as root",
        "Set a non-root 'user' for the service."),
    "DCMP007": RuleSpec(C.SECURITY, S.LOW, CF.MEDIUM,
        "No user specified (may run as root)",
        "Set an explicit non-root 'user'."),
    "DCMP008": RuleSpec(C.RELIABILITY, S.INFO, CF.LOW,
        "No healthcheck defined",
        "Add a healthcheck so orchestrators can detect unhealthy containers."),
    "DCMP009": RuleSpec(C.RELIABILITY, S.LOW, CF.MEDIUM,
        "No restart policy",
        "Set 'restart' (or deploy.restart_policy) for resilience."),
    "DCMP010": RuleSpec(C.RELIABILITY, S.MEDIUM, CF.MEDIUM,
        "No resource limits",
        "Set memory/CPU limits (deploy.resources.limits or mem_limit/cpus)."),
    "DCMP011": RuleSpec(C.SECRETS, S.HIGH, CF.MEDIUM,
        "Hardcoded password/secret in environment",
        "Use Docker secrets or runtime injection, not literals in the Compose file."),
    "DCMP012": RuleSpec(C.SECRETS, S.CRITICAL, CF.HIGH,
        "Hardcoded API key or credential",
        "Remove the credential and inject it at runtime via secrets."),
    "DCMP013": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Database port published to the host",
        "Do not publish database ports; reach them over the internal network only."),
    "DCMP014": RuleSpec(C.SECURITY, S.MEDIUM, CF.HIGH,
        "Port bound to 0.0.0.0 (all interfaces)",
        "Bind published ports to a specific or loopback address where possible."),
    "DCMP015": RuleSpec(C.SUPPLY_CHAIN, S.MEDIUM, CF.HIGH,
        "Image uses the 'latest' tag",
        "Pin the image to a specific version (ideally a digest)."),
    "DCMP016": RuleSpec(C.SUPPLY_CHAIN, S.MEDIUM, CF.HIGH,
        "Image is not pinned to a version",
        "Specify an explicit image tag or digest."),
    "DCMP017": RuleSpec(C.SECURITY, S.CRITICAL, CF.HIGH,
        "Docker socket mounted into container",
        "Never mount /var/run/docker.sock; it grants host root-equivalent access."),
    "DCMP018": RuleSpec(C.SECURITY, S.HIGH, CF.HIGH,
        "Sensitive host path mounted",
        "Avoid mounting sensitive host paths; mount only what is needed, read-only."),
    "DCMP019": RuleSpec(C.SECURITY, S.LOW, CF.MEDIUM,
        "Host filesystem bind mount",
        "Prefer named volumes; mount host paths read-only when required."),
    "DCMP021": RuleSpec(C.RELIABILITY, S.INFO, CF.MEDIUM,
        "depends_on without a health condition",
        "Use long-form depends_on with 'condition: service_healthy'."),
    "DCMP022": RuleSpec(C.CONFIGURATION, S.MEDIUM, CF.HIGH,
        "depends_on references an undefined service",
        "Reference an existing service or define the missing one."),
    "DCMP023": RuleSpec(C.BEST_PRACTICE, S.INFO, CF.MEDIUM,
        "No explicit networks defined",
        "Define explicit networks to segment services."),
    "DCMP024": RuleSpec(C.SECURITY, S.MEDIUM, CF.MEDIUM,
        "Insecure environment variable (TLS/SSL verification disabled)",
        "Enable TLS/certificate verification."),
    "DCMP025": RuleSpec(C.BEST_PRACTICE, S.INFO, CF.LOW,
        "Debug mode enabled via environment",
        "Disable debug mode in production images."),
}

_DANGEROUS_CAPS = {
    "ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
    "DAC_READ_SEARCH", "DAC_OVERRIDE", "SYS_BOOT", "SYS_TIME", "NET_RAW",
}

_DB_PORTS = {
    "3306": "MySQL", "5432": "PostgreSQL", "27017": "MongoDB", "6379": "Redis",
    "1433": "MSSQL", "1521": "Oracle", "5984": "CouchDB", "9200": "Elasticsearch",
    "11211": "Memcached", "9042": "Cassandra", "8086": "InfluxDB", "2379": "etcd",
    "5672": "RabbitMQ", "15672": "RabbitMQ management",
}

_SENSITIVE_EXACT = {"/", "/etc", "/var", "/usr", "/root", "/boot", "/proc", "/sys", "/dev", "/home"}
_SENSITIVE_PREFIXES = ("/etc/", "/root/", "/boot/", "/proc/", "/sys/", "/dev/")
_DOCKER_SOCK = "/var/run/docker.sock"

_SECRET_KEY_RE = re.compile(r"(PASSWORD|PASSWD|SECRET|PASSPHRASE)", re.IGNORECASE)
_APIKEY_KEY_RE = re.compile(
    r"(API[_-]?KEY|APIKEY|ACCESS[_-]?KEY|AUTH[_-]?TOKEN|TOKEN|PRIVATE[_-]?KEY)",
    re.IGNORECASE,
)
_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_FALSEY = {"false", "0", "no", "off", "disabled", "disable"}
_TRUTHY = {"true", "1", "yes", "on", "enabled", "enable"}


class _Emitter:
    def __init__(self, file_path: str) -> None:
        self._file_path = file_path
        self.findings: list[RuleFinding] = []

    def add(
        self,
        rule_id: str,
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
                file_path=self._file_path,
                line_number=line,
                evidence=evidence,
            )
        )


def make_syntax_finding(file_path: str, message: str, line: int | None) -> RuleFinding:
    """Build the DCMP000 finding for an unparseable Compose file."""
    spec = RULES["DCMP000"]
    return RuleFinding(
        rule_id="DCMP000",
        scanner=SCANNER_NAME,
        category=spec.category,
        severity=spec.severity,
        confidence=spec.confidence,
        title=spec.title,
        description=f"Compose file could not be parsed: {message}",
        recommendation=spec.recommendation,
        file_path=file_path,
        line_number=line,
        evidence=None,
    )


def analyze(root: Any, *, file_path: str) -> list[RuleFinding]:
    """Run every Compose rule against a parsed (line-annotated) model."""
    emit = _Emitter(file_path)

    if not isinstance(root, dict) or not isinstance(root.get("services"), dict):
        emit.add(
            "DCMP000",
            description="The file has no 'services' mapping; it is not a valid Compose file.",
            line=1,
            severity=Severity.LOW,
        )
        return emit.findings

    services: dict[str, Any] = root["services"]
    service_names = set(services.keys())

    _check_missing_networks(root, services, emit)

    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        svc_line = line_of(services, name)

        def sline(key: str, _svc: Any = svc, _default: int | None = svc_line) -> int | None:
            return line_of(_svc, key) or _default

        _check_privilege_flags(svc, sline, emit)
        _check_capabilities(svc, sline, emit)
        _check_user(svc, name, svc_line, sline, emit)
        _check_reliability(svc, name, svc_line, sline, emit)
        _check_environment(svc, sline, emit)
        _check_ports(svc, sline, emit)
        _check_image(svc, sline, emit)
        _check_volumes(svc, sline, emit)
        _check_depends_on(svc, service_names, sline, emit)

    return emit.findings


# --- checks -----------------------------------------------------------------


def _check_missing_networks(root: dict, services: dict, emit: _Emitter) -> None:
    if "networks" not in root and len(services) >= 2:
        emit.add(
            "DCMP023",
            description="No top-level 'networks' are defined; all services share the "
            "default network without segmentation.",
            line=line_of(root, "services"),
        )


def _check_privilege_flags(svc: dict, sline: Any, emit: _Emitter) -> None:
    if svc.get("privileged") is True:
        emit.add("DCMP001", description="Service runs as a privileged container.",
                 line=sline("privileged"), evidence="privileged: true")
    if str(svc.get("network_mode", "")).lower() == "host":
        emit.add("DCMP002", description="Service uses the host network namespace.",
                 line=sline("network_mode"), evidence="network_mode: host")
    if str(svc.get("pid", "")).lower() == "host":
        emit.add("DCMP003", description="Service shares the host PID namespace.",
                 line=sline("pid"), evidence="pid: host")
    if str(svc.get("ipc", "")).lower() == "host":
        emit.add("DCMP004", description="Service shares the host IPC namespace.",
                 line=sline("ipc"), evidence="ipc: host")


def _check_capabilities(svc: dict, sline: Any, emit: _Emitter) -> None:
    cap_add = svc.get("cap_add")
    if not isinstance(cap_add, list):
        return
    dangerous = [str(c).upper() for c in cap_add if str(c).upper() in _DANGEROUS_CAPS]
    if dangerous:
        emit.add(
            "DCMP005",
            description=f"Service adds dangerous capabilities: {', '.join(dangerous)}.",
            line=sline("cap_add"),
            evidence=f"cap_add: {dangerous}",
        )


def _check_user(svc: dict, name: str, svc_line: int | None, sline: Any, emit: _Emitter) -> None:
    if "user" in svc:
        user = str(svc["user"]).split(":")[0]
        if user in {"root", "0"}:
            emit.add("DCMP006", description=f"Service '{name}' explicitly runs as root.",
                     line=sline("user"), evidence=f"user: {svc['user']}")
    else:
        emit.add(
            "DCMP007",
            description=f"Service '{name}' does not set a user and may run as root.",
            line=svc_line,
        )


def _has_resource_limits(svc: dict) -> bool:
    deploy = svc.get("deploy")
    if isinstance(deploy, dict):
        resources = deploy.get("resources")
        if isinstance(resources, dict):
            limits = resources.get("limits")
            if isinstance(limits, dict) and (limits.get("cpus") or limits.get("memory")):
                return True
    return any(svc.get(k) for k in ("mem_limit", "cpus", "cpu_quota", "mem_reservation"))


def _has_restart(svc: dict) -> bool:
    if "restart" in svc:
        return True
    deploy = svc.get("deploy")
    return isinstance(deploy, dict) and "restart_policy" in deploy


def _check_reliability(
    svc: dict, name: str, svc_line: int | None, sline: Any, emit: _Emitter
) -> None:
    if "healthcheck" not in svc:
        emit.add("DCMP008", description=f"Service '{name}' defines no healthcheck.",
                 line=svc_line)
    if not _has_restart(svc):
        emit.add("DCMP009", description=f"Service '{name}' has no restart policy.",
                 line=svc_line)
    if not _has_resource_limits(svc):
        emit.add("DCMP010", description=f"Service '{name}' sets no CPU/memory limits.",
                 line=svc_line)


def _normalize_env(env: Any) -> list[tuple[str, str | None, int | None]]:
    items: list[tuple[str, str | None, int | None]] = []
    if isinstance(env, dict):
        for key, value in env.items():
            items.append((str(key), None if value is None else str(value), line_of(env, key)))
    elif isinstance(env, list):
        for entry in env:
            text = str(entry)
            if "=" in text:
                key, value = text.split("=", 1)
                items.append((key, value, None))
            else:
                items.append((text, None, None))
    return items


def _is_literal(value: str | None) -> bool:
    if not value:
        return False
    return not value.strip().startswith("$")


def _check_environment(svc: dict, sline: Any, emit: _Emitter) -> None:
    env = svc.get("environment")
    default_line = sline("environment")
    for key, value, key_line in _normalize_env(env):
        line = key_line or default_line

        if value and _AWS_ACCESS_KEY_RE.search(value):
            emit.add("DCMP012", description=f"'{key}' contains an AWS access key ID.",
                     line=line, evidence=f"{key}=<redacted>", severity=Severity.CRITICAL)
            continue
        if _APIKEY_KEY_RE.search(key) and _is_literal(value):
            emit.add("DCMP012", description=f"'{key}' is set to a literal credential.",
                     line=line, evidence=f"{key}=<redacted>")
            continue
        if _SECRET_KEY_RE.search(key) and _is_literal(value):
            emit.add("DCMP011", description=f"'{key}' is set to a literal secret value.",
                     line=line, evidence=f"{key}=<redacted>")
            continue

        _check_insecure_env(key, value, line, emit)


def _check_insecure_env(key: str, value: str | None, line: int | None, emit: _Emitter) -> None:
    low_val = (value or "").strip().lower()
    upper_key = key.upper()

    if upper_key == "NODE_TLS_REJECT_UNAUTHORIZED" and low_val == "0":
        emit.add("DCMP024", description="Node.js TLS certificate validation is disabled.",
                 line=line, evidence=f"{key}={value}")
        return
    if ("SSL" in upper_key or "TLS" in upper_key or "VERIFY" in upper_key) and low_val in _FALSEY:
        emit.add("DCMP024", description=f"'{key}' disables TLS/SSL verification.",
                 line=line, evidence=f"{key}={value}")
        return
    if "INSECURE" in upper_key and low_val in _TRUTHY:
        emit.add("DCMP024", description=f"'{key}' enables insecure behaviour.",
                 line=line, evidence=f"{key}={value}")
        return
    if (upper_key == "DEBUG" or upper_key.endswith("_DEBUG")) and low_val in _TRUTHY:
        emit.add("DCMP025", description=f"'{key}' enables debug mode.",
                 line=line, evidence=f"{key}={value}")


def _parse_port(entry: Any) -> tuple[str | None, str | None, str | None]:
    """Return (host_ip, published, target) for a port entry."""
    if isinstance(entry, dict):
        published = entry.get("published")
        target = entry.get("target")
        return (
            str(entry.get("host_ip")) if entry.get("host_ip") is not None else None,
            str(published) if published is not None else None,
            str(target) if target is not None else None,
        )
    text = str(entry).split("/")[0]  # drop protocol
    parts = text.split(":")
    if len(parts) == 1:
        return None, None, parts[0]
    if len(parts) == 2:
        return None, parts[0], parts[1]
    return parts[0], parts[1], parts[2]


def _first_port(value: str | None) -> str | None:
    if not value:
        return None
    return value.split("-")[0].strip()


def _check_ports(svc: dict, sline: Any, emit: _Emitter) -> None:
    ports = svc.get("ports")
    if not isinstance(ports, list):
        return
    line = sline("ports")
    for entry in ports:
        host_ip, published, target = _parse_port(entry)
        published_port = _first_port(published)
        target_port = _first_port(target)

        if host_ip == "0.0.0.0":
            emit.add("DCMP014", description="A port is published on 0.0.0.0 (all interfaces).",
                     line=line, evidence=str(entry))

        db_port = None
        if published_port in _DB_PORTS:
            db_port = published_port
        elif published is None and target_port in _DB_PORTS:
            db_port = target_port
        if db_port:
            emit.add(
                "DCMP013",
                description=f"{_DB_PORTS[db_port]} port {db_port} is published to the host.",
                line=line,
                evidence=str(entry),
            )


def _check_image(svc: dict, sline: Any, emit: _Emitter) -> None:
    image = svc.get("image")
    if not isinstance(image, str) or not image:
        return  # build-only services have no image to pin
    line = sline("image")
    ref = image
    if "@" in ref:  # pinned by digest
        return
    if ":" in ref:
        _, tag = ref.rsplit(":", 1)
        if tag == "latest":
            emit.add("DCMP015", description=f"Image '{image}' uses the mutable 'latest' tag.",
                     line=line, evidence=f"image: {image}")
    else:
        emit.add("DCMP016", description=f"Image '{image}' has no tag (implicitly 'latest').",
                 line=line, evidence=f"image: {image}")


def _parse_volume(entry: Any) -> tuple[str | None, bool]:
    """Return (source, read_only) for a volume entry."""
    if isinstance(entry, dict):
        return (
            str(entry["source"]) if entry.get("source") is not None else None,
            bool(entry.get("read_only", False)),
        )
    parts = str(entry).split(":")
    if len(parts) == 1:
        return None, False  # anonymous volume
    read_only = len(parts) >= 3 and "ro" in parts[2].split(",")
    return parts[0], read_only


def _is_host_path(source: str) -> bool:
    return source.startswith(("/", "./", "../", "~"))


def _is_sensitive_path(source: str) -> bool:
    normalized = source.rstrip("/") or "/"
    if normalized in _SENSITIVE_EXACT:
        return True
    return normalized.startswith(_SENSITIVE_PREFIXES)


def _check_volumes(svc: dict, sline: Any, emit: _Emitter) -> None:
    volumes = svc.get("volumes")
    if not isinstance(volumes, list):
        return
    line = sline("volumes")
    for entry in volumes:
        source, _read_only = _parse_volume(entry)
        if not source:
            continue
        if _DOCKER_SOCK in source or source.rstrip("/").endswith("docker.sock"):
            emit.add("DCMP017", description="The Docker socket is mounted into the container.",
                     line=line, evidence=str(entry))
        elif _is_host_path(source) and _is_sensitive_path(source):
            emit.add("DCMP018", description=f"Sensitive host path '{source}' is mounted.",
                     line=line, evidence=str(entry))
        elif _is_host_path(source):
            emit.add("DCMP019", description=f"Host path '{source}' is bind-mounted.",
                     line=line, evidence=str(entry))


def _check_depends_on(svc: dict, service_names: set[str], sline: Any, emit: _Emitter) -> None:
    depends_on = svc.get("depends_on")
    if depends_on is None:
        return
    line = sline("depends_on")

    if isinstance(depends_on, list):
        for dep in depends_on:
            if dep not in service_names:
                emit.add("DCMP022", description=f"depends_on references undefined service '{dep}'.",
                         line=line, evidence=str(dep))
        emit.add(
            "DCMP021",
            description="depends_on uses the short form without a health condition.",
            line=line,
            evidence=f"depends_on: {depends_on}",
        )
    elif isinstance(depends_on, dict):
        for dep, cfg in depends_on.items():
            if dep not in service_names:
                emit.add("DCMP022", description=f"depends_on references undefined service '{dep}'.",
                         line=line, evidence=str(dep))
            if not (isinstance(cfg, dict) and cfg.get("condition")):
                emit.add(
                    "DCMP021",
                    description=f"depends_on '{dep}' has no health condition.",
                    line=line,
                    evidence=f"{dep}: {cfg}",
                )
