"""devops-auditor - command-line interface for CI/CD and local use.

Runs the SAME deterministic scanner engine the API uses (``services.scan_engine``)
with no database or network, so it is safe to run inside any CI pipeline or on a
developer's machine.

Commands:
    devops-auditor scan <path>            Scan a directory; print findings.
    devops-auditor check [path]           Dev-friendly scan of the cwd (or path).
    devops-auditor policy check <path> --policy p.yaml
    devops-auditor sbom <path>            Emit a CycloneDX SBOM.

Common options: --format text|json|sarif, --output FILE, --changed (scan only
git-changed files), --fail-on critical|high|medium|low|info (default: high).

Exit codes:
    0  success - no failures over the configured threshold / policy passed
    1  security or policy failure (findings at/above threshold, or policy FAIL)
    2  configuration or runtime error (bad path, invalid policy, etc.)
"""

from __future__ import annotations

import argparse
import json
import subprocess  # noqa: S404 - fixed argv, no shell, read-only `git diff`
import sys
from pathlib import Path
from typing import Any

from core.config import Settings
from scanners.finding import RuleFinding
from services.dependencies import build_cyclonedx, parse_manifests
from services.policy_engine import PolicyError, evaluate, parse_policy
from services.risk import RiskInput, assess_risk
from services.scan_engine import scan_repository

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_ERROR = 2

_SEV_ORDER = ["info", "low", "medium", "high", "critical"]
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}
_SEV_ICON = {"critical": "✗", "high": "✗", "medium": "!", "low": "·", "info": "·"}
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def _v(value: object) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _settings() -> Settings:
    # No .env / DB needed for the pure engine; disable the LLM explicitly.
    return Settings(_env_file=None, llm_provider="none")


def _changed_paths(root: Path) -> set[str] | None:
    """Return git-changed files relative to HEAD, or None if unavailable."""
    try:
        out = subprocess.run(  # noqa: S603
            ["git", "-C", str(root), "diff", "--name-only", "HEAD"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        staged = subprocess.run(  # noqa: S603
            ["git", "-C", str(root), "diff", "--name-only", "--cached"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 and staged.returncode != 0:
        return None
    paths = {ln.strip() for ln in (out.stdout + staged.stdout).splitlines() if ln.strip()}
    return paths or set()


def _scan(root: Path, *, changed: bool) -> list[RuleFinding]:
    only = _changed_paths(root) if changed else None
    return scan_repository(root, _settings(), only_paths=only)


def _finding_dicts(findings: list[RuleFinding]) -> list[dict[str, Any]]:
    out = []
    for f in findings:
        risk = assess_risk(
            RiskInput(
                rule_id=f.rule_id, scanner=f.scanner, category=_v(f.category),
                severity=_v(f.severity), confidence=_v(f.confidence),
                title=f.title, description=f.description or "", evidence=f.evidence,
                file_path=f.file_path,
            )
        ).score
        out.append(
            {
                "rule_id": f.rule_id, "scanner": f.scanner, "category": _v(f.category),
                "severity": _v(f.severity), "confidence": _v(f.confidence),
                "title": f.title, "file": f.file_path, "line": f.line_number,
                "recommendation": f.recommendation, "risk_score": risk, "is_new": False,
            }
        )
    return out


# --- output renderers -------------------------------------------------------

def _render_text(findings: list[dict], *, gate: str, risk: int) -> str:
    lines = ["", "DevOps AI Auditor", ""]
    if not findings:
        lines.append("✓ No findings")
    else:
        lines.append(f"{len(findings)} issue(s) found")
        lines.append("")
        for f in sorted(findings, key=lambda x: -_SEV_RANK.get(x["severity"], 0)):
            icon = _SEV_ICON.get(f["severity"], "·")
            loc = f.get("file") or "?"
            line = f":{f['line']}" if f.get("line") else ""
            lines.append(f"{icon} {f['severity'].upper():<8} {f['title']}")
            lines.append(f"  {f['rule_id']}  {loc}{line}")
    lines += ["", f"Risk: {risk}/100", f"Gate: {gate.upper()}", ""]
    return "\n".join(lines)


def _render_sarif(findings: list[dict], repo: str) -> str:
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    for f in findings:
        if f["rule_id"] not in rule_index:
            rule_index[f["rule_id"]] = len(rules)
            rules.append(
                {
                    "id": f["rule_id"], "name": f["rule_id"],
                    "shortDescription": {"text": f["title"]},
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL.get(f["severity"], "warning")
                    },
                    "properties": {
                        "category": f["category"],
                        "tags": [f["category"], f["scanner"]],
                    },
                }
            )
    results = []
    for f in findings:
        result: dict[str, Any] = {
            "ruleId": f["rule_id"], "ruleIndex": rule_index[f["rule_id"]],
            "level": _SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["title"]},
        }
        if f.get("file"):
            physical: dict[str, Any] = {"artifactLocation": {"uri": f["file"]}}
            if f.get("line"):
                physical["region"] = {"startLine": f["line"]}
            result["locations"] = [{"physicalLocation": physical}]
        results.append(result)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {
                    "name": "DevOps AI Auditor", "version": "0.1.0", "rules": rules,
                }},
                "automationDetails": {"id": repo},
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        print(text)


def _threshold_fail(findings: list[dict], fail_on: str) -> bool:
    cutoff = _SEV_RANK.get(fail_on, _SEV_RANK["high"])
    return any(_SEV_RANK.get(f["severity"], 0) >= cutoff for f in findings)


# --- command handlers -------------------------------------------------------

def _cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return EXIT_ERROR
    findings = _finding_dicts(_scan(root, changed=args.changed))
    risk = max((f["risk_score"] for f in findings), default=0)

    gate = "pass"
    if args.policy:
        try:
            policy = parse_policy(Path(args.policy).read_text(encoding="utf-8"))
        except (OSError, PolicyError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        result = evaluate(policy, findings, environment=args.environment)
        gate = result.status
    elif _threshold_fail(findings, args.fail_on):
        gate = "fail"

    fmt = args.format
    if fmt == "json":
        _emit(json.dumps({"findings": findings, "risk": risk, "gate": gate}, indent=2), args.output)
    elif fmt == "sarif":
        _emit(_render_sarif(findings, root.name), args.output)
    else:
        _emit(_render_text(findings, gate=gate, risk=risk), args.output)

    return EXIT_FAIL if gate == "fail" else EXIT_OK


def _cmd_policy_check(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return EXIT_ERROR
    try:
        policy = parse_policy(Path(args.policy).read_text(encoding="utf-8"))
    except (OSError, PolicyError) as exc:
        print(f"error: invalid policy: {exc}", file=sys.stderr)
        return EXIT_ERROR
    findings = _finding_dicts(_scan(root, changed=args.changed))
    result = evaluate(policy, findings, environment=args.environment)
    if args.format == "json":
        _emit(json.dumps(result.as_dict(), indent=2), args.output)
    else:
        lines = [f"Policy: {policy['name']}", f"Result: {result.status.upper()}", ""]
        for r in result.rules:
            mark = "✓" if r.passed else "✗"
            lines.append(f"{mark} {r.id} ({r.action}) - {r.matched} match(es)")
        _emit("\n".join(lines), args.output)
    return EXIT_FAIL if result.status == "fail" else EXIT_OK


def _cmd_sbom(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return EXIT_ERROR
    manifests: list[tuple[str, str]] = []
    for p in root.rglob("*"):
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            try:
                manifests.append((rel, p.read_text(encoding="utf-8", errors="ignore")))
            except OSError:
                continue
    components = parse_manifests(manifests)
    sbom = build_cyclonedx(root.name, components)
    _emit(json.dumps(sbom, indent=2), args.output)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devops-auditor",
        description="Deterministic DevOps security auditor (CI/CD + local).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--format", choices=["text", "json", "sarif"], default="text")
        sp.add_argument("--output", help="Write output to a file instead of stdout.")
        sp.add_argument("--changed", action="store_true", help="Scan only git-changed files.")
        sp.add_argument("--environment", help="Environment name for policy scoping.")

    scan = sub.add_parser("scan", help="Scan a directory for findings.")
    scan.add_argument("path")
    scan.add_argument("--fail-on", choices=_SEV_ORDER, default="high",
                      help="Exit 1 if any finding is at/above this severity (default: high).")
    scan.add_argument("--policy", help="Gate on a policy YAML instead of --fail-on.")
    _add_common(scan)
    scan.set_defaults(func=_cmd_scan)

    check = sub.add_parser("check", help="Dev-friendly scan of the current directory.")
    check.add_argument("path", nargs="?", default=".")
    check.add_argument("--fail-on", choices=_SEV_ORDER, default="high")
    check.add_argument("--policy")
    _add_common(check)
    check.set_defaults(func=_cmd_scan)

    policy = sub.add_parser("policy", help="Policy operations.")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    pcheck = policy_sub.add_parser("check", help="Scan + evaluate a policy.")
    pcheck.add_argument("path")
    pcheck.add_argument("--policy", required=True, help="Path to the policy YAML.")
    _add_common(pcheck)
    pcheck.set_defaults(func=_cmd_policy_check)

    sbom = sub.add_parser("sbom", help="Generate a CycloneDX SBOM.")
    sbom.add_argument("path")
    sbom.add_argument("--output")
    sbom.set_defaults(func=_cmd_sbom)

    return parser


def _quiet_logging() -> None:
    """Send logs to stderr at ERROR+ so stdout carries only machine output."""
    import logging

    import structlog

    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=False,
    )

    # If the app already configured stdlib logging to stdout (e.g. in a shared
    # process or test run), force every root handler onto stderr at ERROR so no
    # log line can corrupt the machine-readable output on stdout.
    root = logging.getLogger()
    root.setLevel(logging.ERROR)
    root.handlers = [logging.StreamHandler(sys.stderr)]


def main(argv: list[str] | None = None) -> int:
    _quiet_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result: int = args.func(args)
        return result
    except KeyboardInterrupt:  # pragma: no cover
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - surface as runtime error, exit 2
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
