"""Terraform module model.

Terraform is evaluated per directory (a module), so files in the same directory
are analysed together. This module turns parsed HCL files into typed objects and
builds the symbol tables needed for reference/usage analysis.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from scanners.terraform.parser import LineIndex

_VAR_RE = re.compile(r"\bvar\.([A-Za-z_][A-Za-z0-9_]*)")
_LOCAL_RE = re.compile(r"\blocal\.([A-Za-z_][A-Za-z0-9_]*)")
_MODULE_RE = re.compile(r"\bmodule\.([A-Za-z_][A-Za-z0-9_]*)")
_DATA_RE = re.compile(r"\bdata\.([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)")
_RESOURCE_REF_RE = re.compile(r"\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\.([A-Za-z_][A-Za-z0-9_]*)")


@dataclass
class TfResource:
    rtype: str
    name: str
    body: dict
    file_path: str
    index: LineIndex

    @property
    def address(self) -> str:
        return f"{self.rtype}.{self.name}"

    @property
    def line(self) -> int | None:
        return self.index.block_line("resource", self.rtype, self.name)

    def attr_line(self, key: str) -> int | None:
        rng = self.index.block_range("resource", self.rtype, self.name)
        start, end = rng if rng else (None, None)
        return self.index.attr_line(start, end, key)


@dataclass
class TfVariable:
    name: str
    body: dict
    file_path: str
    index: LineIndex

    @property
    def line(self) -> int | None:
        return self.index.block_line("variable", self.name)


@dataclass
class TfFile:
    file_path: str
    parsed: dict
    index: LineIndex


@dataclass(frozen=True, slots=True)
class Scope:
    """A block whose body may contain references (for validation/usage)."""

    body: dict
    file_path: str
    line: int | None
    label: str


@dataclass
class TfModule:
    directory: str
    resources: list[TfResource] = field(default_factory=list)
    variables: list[TfVariable] = field(default_factory=list)
    data_addresses: set[str] = field(default_factory=set)
    module_names: set[str] = field(default_factory=set)
    local_names: set[str] = field(default_factory=set)
    resource_addresses: set[str] = field(default_factory=set)
    resource_types: set[str] = field(default_factory=set)
    reference_scopes: list[Scope] = field(default_factory=list)
    provider_scopes: list[Scope] = field(default_factory=list)


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def walk_strings(value: Any) -> Iterator[str]:
    """Yield every string leaf in a nested dict/list structure."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_strings(item)


def build_module(directory: str, files: list[TfFile]) -> TfModule:
    """Combine parsed files from one directory into a module model."""
    module = TfModule(directory=directory)

    for tf in files:
        parsed, index, path = tf.parsed, tf.index, tf.file_path

        for entry in _as_list(parsed.get("resource")):
            for rtype, named in entry.items():
                for name, body in named.items():
                    body = body if isinstance(body, dict) else {}
                    resource = TfResource(rtype, name, body, path, index)
                    module.resources.append(resource)
                    module.resource_addresses.add(resource.address)
                    module.resource_types.add(rtype)
                    module.reference_scopes.append(
                        Scope(body, path, index.block_line("resource", rtype, name),
                              f"{rtype}.{name}")
                    )

        for entry in _as_list(parsed.get("data")):
            for dtype, named in entry.items():
                for name in named:
                    module.data_addresses.add(f"{dtype}.{name}")

        for entry in _as_list(parsed.get("variable")):
            for name, body in entry.items():
                module.variables.append(
                    TfVariable(name, body if isinstance(body, dict) else {}, path, index)
                )

        for entry in _as_list(parsed.get("module")):
            for name, body in entry.items():
                module.module_names.add(name)
                module.reference_scopes.append(
                    Scope(body if isinstance(body, dict) else {}, path,
                          index.block_line("module", name), f"module.{name}")
                )

        for entry in _as_list(parsed.get("locals")):
            if isinstance(entry, dict):
                module.local_names.update(entry.keys())
                module.reference_scopes.append(
                    Scope(entry, path, index.block_line("locals"), "locals")
                )

        for entry in _as_list(parsed.get("output")):
            for name, body in entry.items():
                module.reference_scopes.append(
                    Scope(body if isinstance(body, dict) else {}, path,
                          index.block_line("output", name), f"output.{name}")
                )

        for entry in _as_list(parsed.get("provider")):
            for name, body in entry.items():
                module.provider_scopes.append(
                    Scope(body if isinstance(body, dict) else {}, path,
                          index.block_line("provider", name), f"provider.{name}")
                )

    return module


def extract_references(value: Any) -> dict[str, set[str]]:
    """Extract var/local/module/data/resource references from a value tree."""
    refs: dict[str, set[str]] = {
        "var": set(), "local": set(), "module": set(), "data": set(), "resource": set(),
    }
    for text in walk_strings(value):
        refs["var"].update(_VAR_RE.findall(text))
        refs["local"].update(_LOCAL_RE.findall(text))
        refs["module"].update(_MODULE_RE.findall(text))
        refs["data"].update(f"{d}.{n}" for d, n in _DATA_RE.findall(text))
        for rtype, name in _RESOURCE_REF_RE.findall(text):
            # Skip the reserved namespaces handled above.
            if rtype in {"var", "local", "module", "data"}:
                continue
            refs["resource"].add(f"{rtype}.{name}")
    return refs


def used_variable_names(module: TfModule) -> set[str]:
    """All variable names referenced anywhere in the module."""
    used: set[str] = set()
    for scope in module.reference_scopes:
        used.update(extract_references(scope.body)["var"])
    # Variables may also be referenced in other variables' defaults.
    for variable in module.variables:
        used.update(extract_references(variable.body.get("default"))["var"])
    return used
