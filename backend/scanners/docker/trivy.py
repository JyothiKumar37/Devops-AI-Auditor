"""Optional Trivy adapter for base-image vulnerability scanning (DCK013).

Trivy scans a container image for known CVEs. Because that requires pulling the
image and consulting a vulnerability database (network, time), it is only used
when the binary is present and explicitly enabled in configuration. Results are
summarised per image (counts by severity) to keep findings actionable rather
than emitting one finding per CVE.
"""

from __future__ import annotations

import json
import shutil
import subprocess

from core.logging import get_logger
from models.enums import Confidence, FindingCategory, Severity
from scanners.finding import RuleFinding

logger = get_logger(__name__)

SCANNER_NAME = "trivy"
_BINARY = "trivy"

_TRIVY_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


def is_available() -> bool:
    """True if the trivy binary is on PATH."""
    return shutil.which(_BINARY) is not None


def parse_trivy_image_json(
    output: str, file_path: str, image: str, line: int | None
) -> list[RuleFinding]:
    """Summarise Trivy image JSON into per-image findings (pure; unit-testable)."""
    try:
        report = json.loads(output or "{}")
    except json.JSONDecodeError:
        return []

    counts: dict[str, int] = {}
    for result in report.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = str(vuln.get("Severity", "UNKNOWN")).upper()
            counts[sev] = counts.get(sev, 0) + 1

    findings: list[RuleFinding] = []
    for sev_name in ("CRITICAL", "HIGH"):
        count = counts.get(sev_name, 0)
        if count == 0:
            continue
        findings.append(
            RuleFinding(
                rule_id="DCK013",
                scanner=SCANNER_NAME,
                category=FindingCategory.SUPPLY_CHAIN,
                severity=_TRIVY_SEVERITY[sev_name],
                confidence=Confidence.HIGH,
                title=f"Base image '{image}' has {count} {sev_name.lower()} vulnerabilities",
                description=f"Trivy reported {count} {sev_name.lower()}-severity "
                f"vulnerabilities in base image '{image}'.",
                recommendation="Update the base image to a patched version or a slimmer variant.",
                file_path=file_path,
                line_number=line,
                evidence=f"{image}: {sev_name}={count}",
            )
        )
    return findings


def run(image: str, file_path: str, line: int | None, *, timeout: int = 120) -> list[RuleFinding]:
    """Run trivy against a container image reference. Never raises."""
    if not is_available():
        return []
    try:
        completed = subprocess.run(  # noqa: S603 - fixed binary, no shell
            [
                _BINARY,
                "image",
                "--quiet",
                "--format",
                "json",
                "--severity",
                "CRITICAL,HIGH",
                image,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("trivy_failed", image=image, error=str(exc))
        return []

    return parse_trivy_image_json(completed.stdout, file_path, image, line)
