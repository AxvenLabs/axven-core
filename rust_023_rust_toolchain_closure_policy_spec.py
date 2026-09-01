#!/usr/bin/env python3
"""RUST-023 static policy: exact Rust toolchain closure stays non-production and fail-closed."""
from __future__ import annotations

import ast
from pathlib import Path

VERIFIER = Path("rust_023_rust_toolchain_closure.py")
WORKFLOW = Path(".github/workflows/native-rust-toolchain-closure.yml")
DOC = Path("RUST_023.md")

EXPECTED_IMAGE = (
    "quay.io/pypa/manylinux_2_28_x86_64@"
    "sha256:443eabd378e140996780a772e12c1a1ef10551da933fe76d74a1bab61f68a7b7"
)
EXPECTED_RUSTC = "rustc 1.98.0 (88d9e12ae 2026-08-18)"
EXPECTED_CARGO = "cargo 1.98.0 (797e8a9bc 2026-08-05)"
FORBIDDEN_IMPORT_ROOTS = {
    "socket",
    "subprocess",
    "urllib",
    "http",
    "requests",
    "ftplib",
    "ssl",
    "asyncio",
}
FORBIDDEN_TEXT = (
    "actions/upload-artifact",
    "id-token: write",
    "contents: write",
    "packages: write",
    "attestations: write",
    "docker push",
    "maturin publish",
    "twine upload",
    "gh release",
)


def _imports(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def _assert_no_process_escape(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in {"eval", "exec", "compile", "__import__"}:
                raise AssertionError(f"forbidden dynamic execution: {func.id}")
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == "os" and func.attr in {"system", "popen", "spawnl", "spawnlp", "spawnv", "spawnvp"}:
                    raise AssertionError(f"forbidden process escape: os.{func.attr}")


def main() -> None:
    verifier = VERIFIER.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    doc = DOC.read_text(encoding="utf-8")
    tree = ast.parse(verifier)

    imports = _imports(tree)
    bad = sorted(imports & FORBIDDEN_IMPORT_ROOTS)
    if bad:
        raise AssertionError(f"RUST-023 verifier imports forbidden network/process modules: {bad}")
    _assert_no_process_escape(tree)
    for token in ("import axven", "from axven", "GITHUB_", "docker", "git "):
        if token in verifier:
            raise AssertionError(f"RUST-023 verifier must remain detached from producer/runtime context: {token!r}")
    for required in (
        'SCHEMA = "axven-rust-toolchain-closure-v1"',
        'TOOLCHAIN = "1.98.0-x86_64-unknown-linux-gnu"',
        "toolchain directory symlink rejected",
        "toolchain file symlink rejected",
        "manifest JSON is not canonical",
        "toolchain SHA-256 mismatch",
        "10/10 GREEN",
    ):
        if required not in verifier:
            raise AssertionError(f"missing verifier fail-closed contract: {required}")
    print("[GREEN] RUST-023 verifier is stdlib-only, process/network independent and exact-set fail-closed")

    if "permissions:\n  contents: read\n" not in workflow:
        raise AssertionError("workflow must remain contents: read only")
    if EXPECTED_IMAGE not in workflow:
        raise AssertionError("immutable manylinux image digest changed")
    for required in (
        "rustup toolchain install 1.98.0 --profile minimal",
        'rustc --version | grep -F "rustc 1.98.0 (88d9e12ae 2026-08-18)"',
        'cargo --version | grep -F "cargo 1.98.0 (797e8a9bc 2026-08-05)"',
        "rust_023_rust_toolchain_closure.py collect",
        "rust_023_rust_toolchain_closure.py verify",
        "rust_023_rust_toolchain_closure.py selftest",
        "--network none",
        ":/rust-toolchain:ro",
        "PATH=/rust-toolchain/bin:",
        "rustc --target x86_64-unknown-linux-gnu",
    ):
        if required not in workflow:
            raise AssertionError(f"workflow missing RUST-023 boundary: {required}")
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in workflow.lower():
            raise AssertionError(f"forbidden workflow privilege/publication path: {forbidden}")
    if workflow.count("rust_023_rust_toolchain_closure.py verify") < 2:
        raise AssertionError("toolchain closure must be verified both before and after isolated consumption")
    print("[GREEN] workflow captures, verifies, consumes read-only and reverifies the exact Rust 1.98.0 closure")

    if EXPECTED_RUSTC not in doc or EXPECTED_CARGO not in doc:
        raise AssertionError("documentation must pin exact rustc/cargo build identities")
    for required in (
        "does not independently authenticate the upstream Rust distribution",
        "Production consensus remains Python-authoritative",
        "does not publish",
        "RUST-024",
    ):
        if required not in doc:
            raise AssertionError(f"RUST-023 documentation boundary missing: {required}")
    print("[GREEN] documentation states the remaining upstream-distribution trust boundary without overclaiming")

    for production_path in (
        '"axven/',
        '"p2p.py"',
        '"rpc.py"',
        '"wallet.py"',
        '"chain.py"',
        '"consensus.py"',
    ):
        if production_path in workflow:
            raise AssertionError(f"RUST-023 workflow must not target production path: {production_path}")
    print("[GREEN] RUST-023 changes only supply-chain proof/CI paths; production routing remains untouched")

    print("RUST-023 verified Rust toolchain closure policy contract: 4/4 GREEN")


if __name__ == "__main__":
    main()
