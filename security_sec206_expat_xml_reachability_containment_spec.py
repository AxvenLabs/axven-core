#!/usr/bin/env python3
"""SEC-206: keep Expat-backed XML parsing outside Axven's trusted runtime surface."""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# These are Axven's executable/runtime trust-boundary modules.  If XML parsing is
# ever intentionally introduced, it must come through a new security review
# rather than silently inheriting the host CPython/libexpat attack surface.
PRODUCTION_PATHS = (
    "axven.py",
    "axven_cli.py",
    "axven_console.py",
    "axven_core.py",
    "canonical_ops.py",
    "core.py",
    "datadir.py",
    "doctor.py",
    "explorer.py",
    "p2p.py",
    "p2p_tx_bounds.py",
    "rpc.py",
    "wallet.py",
    "tools/peer_probe.py",
    "tools/public_peer_acceptance.py",
    "tools/seed_health.py",
)

# xml.*, xmlrpc and plistlib can reach Expat-backed parsing in CPython.
# pyexpat/_elementtree are the lower-level parser surfaces themselves.
PROHIBITED_PREFIXES = (
    "xml",
    "xmlrpc",
    "pyexpat",
    "_elementtree",
    "plistlib",
)


def _is_prohibited(module_name: str) -> bool:
    return any(
        module_name == prefix or module_name.startswith(prefix + ".")
        for prefix in PROHIBITED_PREFIXES
    )


def _constant_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _scan_source(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_prohibited(alias.name):
                    violations.append(f"{path.name}:{node.lineno}: import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if _is_prohibited(module):
                violations.append(f"{path.name}:{node.lineno}: from {module} import ...")
        elif isinstance(node, ast.Call) and node.args:
            # Catch the common constant-string dynamic-import escape hatches.
            target = None
            if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                target = _constant_string(node.args[0])
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "import_module"
            ):
                target = _constant_string(node.args[0])
            if target and _is_prohibited(target):
                violations.append(
                    f"{path.name}:{node.lineno}: dynamic import of {target}"
                )

    return violations


def main() -> None:
    missing = [name for name in PRODUCTION_PATHS if not (ROOT / name).is_file()]
    assert not missing, f"SEC-206 production path set drifted; missing: {missing}"

    violations: list[str] = []
    for relative in PRODUCTION_PATHS:
        violations.extend(_scan_source(ROOT / relative))
    assert not violations, "SEC-206 XML parser reachability violation:\n" + "\n".join(violations)

    # Import the main runtime modules in a clean child interpreter and verify
    # that the current dependency graph does not pull Expat-backed parsers in
    # transitively at import time.
    probe = r'''
import sys
import axven, core, datadir, explorer, p2p, rpc, wallet
bad = sorted(
    name for name in sys.modules
    if name == "pyexpat"
    or name == "_elementtree"
    or name == "plistlib"
    or name == "xml"
    or name.startswith("xml.")
    or name == "xmlrpc"
    or name.startswith("xmlrpc.")
)
if bad:
    raise SystemExit("SEC-206 transitive XML parser modules loaded: " + ", ".join(bad))
'''
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, (result.stdout + result.stderr).strip()

    print(
        "SEC-206 Expat/XML reachability containment: "
        f"{len(PRODUCTION_PATHS)}/{len(PRODUCTION_PATHS)} production paths GREEN"
    )


if __name__ == "__main__":
    main()
