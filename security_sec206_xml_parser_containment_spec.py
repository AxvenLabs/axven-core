#!/usr/bin/env python3
"""SEC-206: keep XML/Expat parsers outside the production Axven surface."""
from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path

import axven

ROOT = Path(__file__).resolve().parent
BANNED_IMPORT_ROOTS = {
    "xml",
    "pyexpat",
    "lxml",
    "defusedxml",
    "xmltodict",
    "xmlschema",
    "elementpath",
}
BANNED_DEPENDENCY_TOKENS = ("xml", "expat")


def _is_banned_module(name: str | None) -> bool:
    if not name:
        return False
    return name.split(".", 1)[0].lower() in BANNED_IMPORT_ROOTS


def _scan_tree(tree: ast.AST, label: str) -> list[str]:
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_banned_module(alias.name):
                    violations.append(f"{label}:{node.lineno}: import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if _is_banned_module(node.module):
                violations.append(f"{label}:{node.lineno}: from {node.module} import ...")
        elif isinstance(node, ast.Call) and node.args:
            func = node.func
            dynamic_loader = (
                isinstance(func, ast.Name) and func.id in {"__import__", "import_module"}
            ) or (
                isinstance(func, ast.Attribute) and func.attr == "import_module"
            )
            target = node.args[0]
            if (
                dynamic_loader
                and isinstance(target, ast.Constant)
                and isinstance(target.value, str)
                and _is_banned_module(target.value)
            ):
                violations.append(
                    f"{label}:{node.lineno}: dynamic import {target.value!r}"
                )
    return violations


def _scan_file(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    return _scan_tree(ast.parse(source, filename=str(path)), path.name)


def _dependency_name(spec: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", spec)
    assert match, spec
    return match.group(1).lower().replace("_", "-")


def main():
    checks = 0
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    production_modules = pyproject["tool"]["setuptools"]["py-modules"]
    assert production_modules
    violations: list[str] = []
    for module in production_modules:
        path = ROOT / f"{module}.py"
        assert path.is_file(), path
        violations.extend(_scan_file(path))
    assert not violations, "\n".join(violations)
    checks += 1
    print(
        f"[GREEN] {len(production_modules)} packaged production modules contain no XML/Expat parser imports"
    )

    dependency_specs = list(pyproject["project"].get("dependencies", []))
    for specs in pyproject["project"].get("optional-dependencies", {}).values():
        dependency_specs.extend(specs)
    dependency_names = [_dependency_name(spec) for spec in dependency_specs]
    offenders = [
        name
        for name in dependency_names
        if any(token in name for token in BANNED_DEPENDENCY_TOKENS)
    ]
    assert not offenders, offenders
    checks += 1
    print("[GREEN] runtime and optional dependency metadata introduce no XML/Expat parser package")

    synthetic = """
import xml.etree.ElementTree
from xml.parsers import expat
from defusedxml import ElementTree
import importlib
__import__('pyexpat')
importlib.import_module('lxml.etree')
"""
    synthetic_violations = _scan_tree(ast.parse(synthetic), "synthetic")
    assert len(synthetic_violations) == 5, synthetic_violations
    checks += 1
    print("[GREEN] containment scanner rejects static and dynamic parser-import patterns")

    security_policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "XML/Expat parsing is not part of the production Axven runtime surface" in security_policy
    assert "requires explicit security" in security_policy
    checks += 1
    print("[GREEN] security policy makes XML parser introduction an explicit review boundary")

    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    for name in ("SECURITY.md", "security_sec206_xml_parser_containment_spec.py"):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest covers the SEC-206 policy and regression contract")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] canonical chain identity unchanged")

    assert checks == 6, checks
    print("SEC-206 XML parser containment: 6/6 GREEN")


if __name__ == "__main__":
    main()
