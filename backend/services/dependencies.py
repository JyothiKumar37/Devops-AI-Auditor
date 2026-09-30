"""Dependency inventory + CycloneDX SBOM generation.

Parses the dependency manifests that are practical to read deterministically and
offline - Node (package.json, package-lock.json) and Python (requirements*.txt,
pyproject.toml, poetry.lock) - into a de-duplicated component inventory, and
renders a CycloneDX 1.5 JSON SBOM.

IMPORTANT: this module performs NO vulnerability lookup. There is no bundled
vulnerability database, so it never fabricates CVEs or severity counts. It
reports the software bill of materials (what is present, direct vs transitive)
only; vulnerability enrichment is left to a real data source if one is added.
"""

from __future__ import annotations

import json
import re
import tomllib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

NPM = "npm"
PYPI = "pypi"

# Names (basename, lower-cased) we recognise as dependency manifests.
_REQUIREMENTS_RE = re.compile(r"^requirements[\w.-]*\.txt$")


def manifest_kind(path: str) -> str | None:
    """Return a manifest kind for a repo path, or None if it is not a manifest."""
    name = PurePosixPath(path).name.lower()
    if name == "package.json":
        return "npm_manifest"
    if name == "package-lock.json":
        return "npm_lock"
    if _REQUIREMENTS_RE.match(name):
        return "pip_requirements"
    if name == "pyproject.toml":
        return "pyproject"
    if name == "poetry.lock":
        return "poetry_lock"
    return None


@dataclass(slots=True)
class Component:
    """A single resolved dependency."""

    name: str
    version: str
    ecosystem: str
    direct: bool = False
    license: str | None = None
    sources: set[str] = field(default_factory=set)

    @property
    def key(self) -> tuple[str, str]:
        return (self.ecosystem, self.name.lower())


_RANGE_CHARS = set("^~>=<* ")
_LEADING_RANGE_RE = re.compile(r"^[\^~>=<=!\s]+")


def _looks_exact(version: str) -> bool:
    return bool(version) and not (set(version) & _RANGE_CHARS) and version[0].isdigit()


def _strip_range(spec: str) -> str:
    """Remove leading range operators (^ ~ >= <= etc.) to expose the version."""
    return _LEADING_RANGE_RE.sub("", spec.strip())


def _clean_npm_spec(spec: str) -> str:
    # Drop leading range operators for a readable version; keep the rest as-is.
    return _strip_range(spec) or spec.strip()


class _Inventory:
    """Accumulates and merges components across manifests."""

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], Component] = {}

    def add(
        self,
        *,
        name: str,
        version: str,
        ecosystem: str,
        direct: bool,
        source: str,
        license: str | None = None,
    ) -> None:
        name = name.strip()
        if not name:
            return
        version = (version or "").strip() or "unknown"
        comp = self._by_key.get((ecosystem, name.lower()))
        if comp is None:
            self._by_key[(ecosystem, name.lower())] = Component(
                name=name,
                version=version,
                ecosystem=ecosystem,
                direct=direct,
                license=license,
                sources={source},
            )
            return
        # Merge: prefer an exact version over a range spec; OR the direct flag.
        comp.direct = comp.direct or direct
        comp.sources.add(source)
        if license and not comp.license:
            comp.license = license
        if _looks_exact(version) and not _looks_exact(comp.version):
            comp.version = version

    def components(self) -> list[Component]:
        return sorted(
            self._by_key.values(), key=lambda c: (c.ecosystem, c.name.lower())
        )


def parse_manifests(files: list[tuple[str, str]]) -> list[Component]:
    """Parse (path, content) manifest files into a merged component inventory."""
    inv = _Inventory()
    for path, content in files:
        kind = manifest_kind(path)
        if kind is None or not content:
            continue
        try:
            if kind == "npm_manifest":
                _parse_package_json(content, path, inv)
            elif kind == "npm_lock":
                _parse_package_lock(content, path, inv)
            elif kind == "pip_requirements":
                _parse_requirements(content, path, inv)
            elif kind == "pyproject":
                _parse_pyproject(content, path, inv)
            elif kind == "poetry_lock":
                _parse_poetry_lock(content, path, inv)
        except (ValueError, TypeError, tomllib.TOMLDecodeError, json.JSONDecodeError):
            # A malformed manifest never breaks the scan; it is simply skipped.
            continue
    return inv.components()


# --- Node ------------------------------------------------------------------


def _parse_package_json(content: str, path: str, inv: _Inventory) -> None:
    data = json.loads(content)
    if not isinstance(data, dict):
        return
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            inv.add(
                name=str(name),
                version=_clean_npm_spec(str(spec)),
                ecosystem=NPM,
                direct=True,
                source=path,
            )


def _parse_package_lock(content: str, path: str, inv: _Inventory) -> None:
    data = json.loads(content)
    if not isinstance(data, dict):
        return
    # Lockfile v2/v3: "packages" keyed by node_modules paths ("" is the root).
    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_path, meta in packages.items():
            if not isinstance(meta, dict) or pkg_path == "":
                continue
            name = str(meta.get("name") or pkg_path.split("node_modules/")[-1])
            version = str(meta.get("version", "unknown"))
            # Nested node_modules => transitive; top-level => could be direct.
            direct = pkg_path.count("node_modules/") == 1
            inv.add(
                name=name,
                version=version,
                ecosystem=NPM,
                direct=direct,
                source=path,
                license=_npm_license(meta),
            )
        return
    # Lockfile v1: "dependencies" tree.
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        _walk_lock_v1(deps, path, inv, top=True)


def _walk_lock_v1(deps: dict, path: str, inv: _Inventory, *, top: bool) -> None:
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        inv.add(
            name=str(name),
            version=str(meta.get("version", "unknown")),
            ecosystem=NPM,
            direct=top,
            source=path,
        )
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            _walk_lock_v1(nested, path, inv, top=False)


def _npm_license(meta: dict) -> str | None:
    lic = meta.get("license")
    if isinstance(lic, str):
        return lic
    if isinstance(lic, dict) and isinstance(lic.get("type"), str):
        return lic["type"]
    return None


# --- Python ----------------------------------------------------------------

_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(==|>=|~=|<=|>|<)?\s*([^#;]*)"
)


def _parse_requirements(content: str, path: str, inv: _Inventory) -> None:
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http://", "https://")):
            continue
        match = _REQ_LINE_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        version = (match.group(3) or "").strip() or "unknown"
        inv.add(name=name, version=version, ecosystem=PYPI, direct=True, source=path)


def _parse_pyproject(content: str, path: str, inv: _Inventory) -> None:
    data = tomllib.loads(content)
    project = data.get("project")
    if isinstance(project, dict) and isinstance(project.get("dependencies"), list):
        for dep in project["dependencies"]:
            name, version = _split_pep508(str(dep))
            inv.add(name=name, version=version, ecosystem=PYPI, direct=True, source=path)
    poetry = (
        data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    )
    poetry_deps = poetry.get("dependencies") if isinstance(poetry, dict) else None
    if isinstance(poetry_deps, dict):
        for name, spec in poetry_deps.items():
            if str(name).lower() == "python":
                continue
            version = spec if isinstance(spec, str) else "unknown"
            inv.add(
                name=str(name), version=_strip_range(str(version)) or "unknown",
                ecosystem=PYPI, direct=True, source=path,
            )


def _parse_poetry_lock(content: str, path: str, inv: _Inventory) -> None:
    data = tomllib.loads(content)
    packages = data.get("package")
    if not isinstance(packages, list):
        return
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = str(pkg.get("name", "")).strip()
        version = str(pkg.get("version", "unknown"))
        # poetry.lock lists the fully-resolved set; category/optional hints exist
        # but transitivity is not explicit, so mark lock entries as transitive
        # and let a manifest mark the direct ones.
        inv.add(name=name, version=version, ecosystem=PYPI, direct=False, source=path)


_PEP508_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(.*)$")


def _split_pep508(dep: str) -> tuple[str, str]:
    match = _PEP508_RE.match(dep)
    if not match:
        return dep.strip(), "unknown"
    name = match.group(1)
    rest = match.group(2).strip()
    version = rest.lstrip("=<>~! ").strip() or "unknown"
    # Cut at any environment marker.
    version = version.split(";")[0].strip() or "unknown"
    return name, version


# --- CycloneDX -------------------------------------------------------------


def _purl(component: Component) -> str:
    name = component.name
    version = component.version if component.version != "unknown" else ""
    if component.ecosystem == NPM:
        # Scoped names (@scope/name) URL-encode the leading '@'.
        enc = name.replace("@", "%40", 1) if name.startswith("@") else name
        base = f"pkg:npm/{enc}"
    else:
        base = f"pkg:pypi/{name.lower()}"
    return f"{base}@{version}" if version else base


def purl_for(component: Component) -> str:
    """Public accessor for a component's package URL (purl)."""
    return _purl(component)


def build_cyclonedx(repository_name: str, components: list[Component]) -> dict[str, Any]:
    """Render the inventory as a CycloneDX 1.5 JSON document."""
    now = datetime.now(UTC).isoformat()
    bom_components = []
    for c in components:
        entry: dict[str, Any] = {
            "type": "library",
            "name": c.name,
            "version": c.version,
            "purl": _purl(c),
            "properties": [
                {"name": "aad:ecosystem", "value": c.ecosystem},
                {"name": "aad:scope", "value": "direct" if c.direct else "transitive"},
            ],
        }
        if c.license:
            entry["licenses"] = [{"license": {"name": c.license}}]
        bom_components.append(entry)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "DevOps AI Auditor", "name": "sbom-generator"}],
            "component": {"type": "application", "name": repository_name},
        },
        "components": bom_components,
    }
