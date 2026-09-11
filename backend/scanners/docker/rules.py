"""Deterministic Dockerfile rule engine.

Every rule is a pure function of the parsed Dockerfile - given the same input it
always produces the same findings (no randomness, no network, no LLM). Each rule
maps to a stable ``DCKnnn`` identifier documented in ``RULES`` below.

Covered checks (the 15 required by the specification):

    DCK001 latest image tag                DCK009 missing multi-stage build
    DCK002 unpinned base image             DCK010 unsafe COPY usage
    DCK003 running as root                 DCK011 ADD misuse
    DCK004 missing USER                    DCK012 missing HEALTHCHECK
    DCK005 secrets in Dockerfile           DCK013 vulnerable base image (Trivy)
    DCK006 risky exposed port              DCK014 suspicious command
    DCK007 inefficient layers              DCK015 package-manager best practice
    DCK008 package cache not cleaned

DCK013 is produced by the optional Trivy adapter, not this rule engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from models.enums import Confidence, FindingCategory, Severity
from scanners.docker.parser import Dockerfile, Instruction
from scanners.finding import RuleFinding

SCANNER_NAME = "docker-rules"


@dataclass(frozen=True, slots=True)
class RuleSpec:
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    title: str
    recommendation: str


RULES: dict[str, RuleSpec] = {
    "DCK001": RuleSpec(
        FindingCategory.SUPPLY_CHAIN, Severity.MEDIUM, Confidence.HIGH,
        "Base image uses the 'latest' tag",
        "Pin the base image to a specific version (ideally by digest) for reproducible builds.",
    ),
    "DCK002": RuleSpec(
        FindingCategory.SUPPLY_CHAIN, Severity.HIGH, Confidence.HIGH,
        "Base image is not pinned to a version",
        "Specify an explicit image tag (ideally a @sha256 digest) instead of implicit latest.",
    ),
    "DCK003": RuleSpec(
        FindingCategory.SECURITY, Severity.HIGH, Confidence.HIGH,
        "Container runs as root (USER root)",
        "Create and switch to a non-root user before the final stage's runtime.",
    ),
    "DCK004": RuleSpec(
        FindingCategory.SECURITY, Severity.HIGH, Confidence.MEDIUM,
        "No USER instruction; container runs as root by default",
        "Add a non-root USER instruction in the final stage.",
    ),
    "DCK005": RuleSpec(
        FindingCategory.SECRETS, Severity.CRITICAL, Confidence.HIGH,
        "Possible secret hard-coded in Dockerfile",
        "Remove secrets from the image; inject them at runtime via env vars or a secrets manager.",
    ),
    "DCK006": RuleSpec(
        FindingCategory.SECURITY, Severity.HIGH, Confidence.HIGH,
        "Sensitive/administrative port exposed",
        "Avoid exposing remote-access or management ports (SSH, RDP, Telnet, unencrypted APIs).",
    ),
    "DCK007": RuleSpec(
        FindingCategory.EFFICIENCY, Severity.LOW, Confidence.MEDIUM,
        "Consecutive RUN instructions create unnecessary layers",
        "Combine related RUN commands with '&&' to reduce image layers and size.",
    ),
    "DCK008": RuleSpec(
        FindingCategory.EFFICIENCY, Severity.MEDIUM, Confidence.HIGH,
        "Package manager cache is not cleaned in the same layer",
        "Clean the cache in the same RUN (rm -rf /var/lib/apt/lists/*, apk --no-cache).",
    ),
    "DCK009": RuleSpec(
        FindingCategory.EFFICIENCY, Severity.LOW, Confidence.LOW,
        "Build tooling in a single-stage image",
        "Use a multi-stage build so build tools and artifacts stay out of the final image.",
    ),
    "DCK010": RuleSpec(
        FindingCategory.SECURITY, Severity.MEDIUM, Confidence.MEDIUM,
        "Entire build context copied into the image",
        "Copy only what is needed and use a .dockerignore to avoid leaking secrets or .git.",
    ),
    "DCK011": RuleSpec(
        FindingCategory.BEST_PRACTICE, Severity.MEDIUM, Confidence.HIGH,
        "ADD misuse",
        "Use COPY for local files; use verified curl/wget (not ADD) for remote URLs.",
    ),
    "DCK012": RuleSpec(
        FindingCategory.RELIABILITY, Severity.INFO, Confidence.LOW,
        "No HEALTHCHECK defined for a service image",
        "Add a HEALTHCHECK so orchestrators can detect an unhealthy container.",
    ),
    "DCK013": RuleSpec(
        FindingCategory.SUPPLY_CHAIN, Severity.HIGH, Confidence.HIGH,
        "Vulnerable base image",
        "Update the base image to a patched version.",
    ),
    "DCK014": RuleSpec(
        FindingCategory.SECURITY, Severity.HIGH, Confidence.HIGH,
        "Suspicious or dangerous command",
        "Avoid piping downloads to a shell, disabling TLS, or overly broad permissions.",
    ),
    "DCK015": RuleSpec(
        FindingCategory.BEST_PRACTICE, Severity.LOW, Confidence.MEDIUM,
        "Package manager best-practice issue",
        "Follow package-manager best practices (pin versions, no-install-recommends, npm ci).",
    ),
}

# Base images that need no tag/user reasoning.
_SPECIAL_IMAGES = {"scratch"}

_SECRET_KEY_RE = re.compile(
    r"\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|API[_-]?KEY|APIKEY|TOKEN|"
    r"ACCESS[_-]?KEY|PRIVATE[_-]?KEY))\s*[=: ]\s*([^\s\"']+)",
    re.IGNORECASE,
)
_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")


def _is_variable_reference(value: str) -> bool:
    """True if the value is a build/run-time variable reference rather than a literal."""
    return value.startswith("$")

_RISKY_PORTS = {
    "22": "SSH",
    "23": "Telnet",
    "3389": "RDP",
    "2375": "unencrypted Docker API",
    "2376": "Docker API",
}

_BUILD_INDICATORS = (
    "go build",
    "mvn ",
    "mvn package",
    "gradle ",
    "npm run build",
    "yarn build",
    "make",
    "gcc ",
    "g++ ",
    "cargo build",
    "dotnet build",
    "dotnet publish",
)

_ARCHIVE_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".gz", ".bz2", ".xz", ".zip", ".tar.bz2", ".tar.xz")


class _Emitter:
    """Accumulates findings, filling in the static parts from ``RULES``."""

    def __init__(self, file_path: str) -> None:
        self._file_path = file_path
        self.findings: list[RuleFinding] = []

    def add(
        self,
        rule_id: str,
        *,
        description: str,
        line: int | None,
        evidence: str | None,
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


def analyze(dockerfile: Dockerfile, *, file_path: str) -> list[RuleFinding]:
    """Run every deterministic rule against a parsed Dockerfile."""
    emit = _Emitter(file_path)

    _check_base_images(dockerfile, emit)
    _check_user(dockerfile, emit)
    _check_secrets(dockerfile, emit)
    _check_exposed_ports(dockerfile, emit)
    _check_layers(dockerfile, emit)
    _check_package_cache(dockerfile, emit)
    _check_multistage(dockerfile, emit)
    _check_copy_add(dockerfile, emit)
    _check_healthcheck(dockerfile, emit)
    _check_suspicious_commands(dockerfile, emit)
    _check_package_manager(dockerfile, emit)

    return emit.findings


# --- individual checks ------------------------------------------------------


def _check_base_images(df: Dockerfile, emit: _Emitter) -> None:
    for from_image in df.froms:
        image = from_image.image
        if not image or image in _SPECIAL_IMAGES or image in df.stage_aliases:
            continue  # scratch or a reference to an earlier build stage
        evidence = from_image.instruction.value
        line = from_image.instruction.line
        if from_image.tag == "latest":
            emit.add(
                "DCK001",
                description=f"Base image '{image}' uses the mutable 'latest' tag.",
                line=line,
                evidence=f"FROM {evidence}",
            )
        elif from_image.tag is None and from_image.digest is None:
            emit.add(
                "DCK002",
                description=f"Base image '{image}' has no tag or digest (implicitly 'latest').",
                line=line,
                evidence=f"FROM {evidence}",
            )


def _final_stage_index(df: Dockerfile) -> int | None:
    return df.froms[-1].stage_index if df.froms else None


def _check_user(df: Dockerfile, emit: _Emitter) -> None:
    final = _final_stage_index(df)
    if final is None:
        return
    final_base = df.froms[-1].image
    users = [i for i in df.by_cmd("USER") if i.stage_index == final]

    if not users:
        if final_base in _SPECIAL_IMAGES:
            return
        emit.add(
            "DCK004",
            description="The final build stage has no USER instruction, so the container "
            "runs as root.",
            line=df.froms[-1].instruction.line,
            evidence=f"FROM {df.froms[-1].instruction.value}",
        )
        return

    last_user = users[-1]
    user_value = last_user.value.split()[0] if last_user.value else ""
    if user_value in {"root", "0"} or user_value.startswith("root:") or user_value.startswith("0:"):
        emit.add(
            "DCK003",
            description="The final stage explicitly switches to the root user.",
            line=last_user.line,
            evidence=f"USER {last_user.value}",
        )


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return f"{value[:2]}****{value[-2:]}"


def _check_secrets(df: Dockerfile, emit: _Emitter) -> None:
    for instr in df.instructions:
        if instr.cmd not in {"ENV", "ARG", "RUN", "LABEL"}:
            continue
        value = instr.value

        if _PRIVATE_KEY_RE.search(value):
            emit.add(
                "DCK005",
                description="A private key appears to be embedded in the Dockerfile.",
                line=instr.line,
                evidence="-----BEGIN PRIVATE KEY----- (redacted)",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
            )
            continue

        aws = _AWS_ACCESS_KEY_RE.search(value)
        if aws:
            emit.add(
                "DCK005",
                description="An AWS access key ID appears to be hard-coded.",
                line=instr.line,
                evidence=f"{instr.cmd} ...{_mask(aws.group(0))}...",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
            )
            continue

        match = _SECRET_KEY_RE.search(value)
        if match:
            secret_value = match.group(2)
            # Ignore variable references such as $VAR or ${VAR}; only literals are secrets.
            if _is_variable_reference(secret_value):
                continue
            emit.add(
                "DCK005",
                description=f"'{match.group(1)}' is assigned a literal value in the image.",
                line=instr.line,
                evidence=f"{instr.cmd} {match.group(1)}={_mask(secret_value)}",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
            )


def _check_exposed_ports(df: Dockerfile, emit: _Emitter) -> None:
    for instr in df.by_cmd("EXPOSE"):
        for token in instr.value.split():
            port = token.split("/")[0]
            if port in _RISKY_PORTS:
                emit.add(
                    "DCK006",
                    description=f"Port {port} ({_RISKY_PORTS[port]}) is exposed.",
                    line=instr.line,
                    evidence=f"EXPOSE {instr.value}",
                )


def _check_layers(df: Dockerfile, emit: _Emitter) -> None:
    previous: Instruction | None = None
    for instr in df.instructions:
        if (
            instr.cmd == "RUN"
            and previous is not None
            and previous.cmd == "RUN"
            and previous.stage_index == instr.stage_index
        ):
            emit.add(
                "DCK007",
                description="Consecutive RUN instructions each create a new image layer.",
                line=instr.line,
                evidence=f"RUN {instr.value[:80]}",
            )
            # Only report the first consecutive pair per file to avoid noise.
            return
        previous = instr


def _check_package_cache(df: Dockerfile, emit: _Emitter) -> None:
    for instr in df.by_cmd("RUN"):
        cmd = instr.value
        low = cmd.lower()

        if "apt-get install" in low and "/var/lib/apt/lists" not in low:
            emit.add(
                "DCK008",
                description="apt-get install without removing /var/lib/apt/lists/* in the "
                "same layer bloats the image.",
                line=instr.line,
                evidence=f"RUN {cmd[:100]}",
            )
        apk_add = re.search(r"\bapk add\b", low)
        if apk_add and "--no-cache" not in low and "/var/cache/apk" not in low:
            emit.add(
                "DCK008",
                description="apk add without --no-cache leaves the package index in the image.",
                line=instr.line,
                evidence=f"RUN {cmd[:100]}",
            )
        if re.search(r"\bpip3?\s+install\b", low) and "--no-cache-dir" not in low:
            emit.add(
                "DCK008",
                description="pip install without --no-cache-dir keeps the wheel cache.",
                line=instr.line,
                evidence=f"RUN {cmd[:100]}",
                severity=Severity.LOW,
            )
        if re.search(r"\b(yum|dnf)\s+install\b", low) and "clean all" not in low:
            emit.add(
                "DCK008",
                description="yum/dnf install without 'clean all' leaves caches in the image.",
                line=instr.line,
                evidence=f"RUN {cmd[:100]}",
                severity=Severity.LOW,
            )


def _check_multistage(df: Dockerfile, emit: _Emitter) -> None:
    if df.stage_count != 1:
        return
    for instr in df.by_cmd("RUN"):
        low = instr.value.lower()
        if any(indicator in low for indicator in _BUILD_INDICATORS):
            emit.add(
                "DCK009",
                description="A compile/build step runs in a single-stage image, so build "
                "tooling ships in the final image.",
                line=instr.line,
                evidence=f"RUN {instr.value[:100]}",
            )
            return


def _iter_path_args(value: str) -> list[str]:
    """Return non-flag arguments of a COPY/ADD instruction."""
    tokens = value.split()
    return [t for t in tokens if not t.startswith("--")]


def _check_copy_add(df: Dockerfile, emit: _Emitter) -> None:
    for instr in df.instructions:
        if instr.cmd not in {"COPY", "ADD"}:
            continue
        args = _iter_path_args(instr.value)
        sources = args[:-1] if len(args) >= 2 else args

        # Unsafe whole-context copy.
        if "." in sources:
            emit.add(
                "DCK010",
                description=f"'{instr.cmd} . ...' copies the entire build context into the image.",
                line=instr.line,
                evidence=f"{instr.cmd} {instr.value}",
            )

        if instr.cmd == "ADD":
            src = sources[0] if sources else ""
            if src.startswith(("http://", "https://")):
                emit.add(
                    "DCK011",
                    description="ADD is used to fetch a remote URL, which bypasses TLS/"
                    "checksum verification.",
                    line=instr.line,
                    evidence=f"ADD {instr.value}",
                )
            elif src and not src.endswith(_ARCHIVE_SUFFIXES) and src != ".":
                emit.add(
                    "DCK011",
                    description="ADD used for a non-archive local file; COPY is safer.",
                    line=instr.line,
                    evidence=f"ADD {instr.value}",
                    severity=Severity.LOW,
                )


def _check_healthcheck(df: Dockerfile, emit: _Emitter) -> None:
    if df.by_cmd("HEALTHCHECK"):
        return
    exposes = df.by_cmd("EXPOSE")
    if exposes:
        emit.add(
            "DCK012",
            description="The image exposes a port but defines no HEALTHCHECK.",
            line=exposes[0].line,
            evidence=f"EXPOSE {exposes[0].value}",
        )


def _check_suspicious_commands(df: Dockerfile, emit: _Emitter) -> None:
    patterns: list[tuple[re.Pattern[str], str, Severity]] = [
        (
            re.compile(r"(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(sh|bash)\b", re.IGNORECASE),
            "A remote script is piped directly into a shell.",
            Severity.HIGH,
        ),
        (
            re.compile(r"\brm\s+-rf\s+/(?:\s|$)"),
            "A destructive 'rm -rf /' command is present.",
            Severity.HIGH,
        ),
        (
            re.compile(r"\bchmod\s+(-R\s+)?777\b"),
            "chmod 777 grants world-writable permissions.",
            Severity.MEDIUM,
        ),
        (
            re.compile(r"(--insecure|-k\b|--no-check-certificate)", re.IGNORECASE),
            "TLS certificate verification is disabled.",
            Severity.MEDIUM,
        ),
        (
            re.compile(r"\bsudo\b"),
            "sudo is unnecessary inside a container build.",
            Severity.LOW,
        ),
    ]
    for instr in df.by_cmd("RUN"):
        value = instr.value
        for pattern, description, severity in patterns:
            if pattern.search(value):
                emit.add(
                    "DCK014",
                    description=description,
                    line=instr.line,
                    evidence=f"RUN {value[:100]}",
                    severity=severity,
                )


def _check_package_manager(df: Dockerfile, emit: _Emitter) -> None:
    for instr in df.by_cmd("RUN"):
        low = instr.value.lower()
        if re.search(r"\bapt-get\s+(?:dist-)?upgrade\b", low):
            emit.add(
                "DCK015",
                description="Running apt-get upgrade in a Dockerfile is discouraged and "
                "non-reproducible.",
                line=instr.line,
                evidence=f"RUN {instr.value[:100]}",
                severity=Severity.MEDIUM,
            )
        if "apt-get install" in low and "--no-install-recommends" not in low:
            emit.add(
                "DCK015",
                description="apt-get install without --no-install-recommends pulls in "
                "unnecessary packages.",
                line=instr.line,
                evidence=f"RUN {instr.value[:100]}",
            )
        if re.search(r"\bnpm\s+install\b", low):
            emit.add(
                "DCK015",
                description="Use 'npm ci' for reproducible, lockfile-based installs in images.",
                line=instr.line,
                evidence=f"RUN {instr.value[:100]}",
            )
