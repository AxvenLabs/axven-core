#!/usr/bin/env python3
"""RUST-024 static policy: upstream Rust distribution authentication stays fail-closed/non-production."""
from __future__ import annotations

import ast
from pathlib import Path

VERIFIER = Path("rust_024_upstream_rust_distribution.py")
WORKFLOW = Path(".github/workflows/native-upstream-rust-distribution.yml")
DOC = Path("RUST_024.md")

URL = "https://static.rust-lang.org/dist/2026-08-20/rust-1.98.0-x86_64-unknown-linux-gnu.tar.xz"
SHA256 = "ed8ee2df70909c88cbaf87a6cfa3920dac00b537de12a6abe6906641e0f5952f"
ARCHIVE_ROOT = "rust-1.98.0-x86_64-unknown-linux-gnu"
IMAGE = "quay.io/pypa/manylinux_2_28_x86_64@sha256:443eabd378e140996780a772e12c1a1ef10551da933fe76d74a1bab61f68a7b7"
RUSTC = "rustc 1.98.0 (88d9e12ae 2026-08-18)"
CARGO = "cargo 1.98.0 (797e8a9bc 2026-08-05)"
FORBIDDEN_IMPORTS = {"socket", "subprocess", "urllib", "http", "requests", "ftplib", "ssl", "asyncio"}
FORBIDDEN_WORKFLOW = (
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
    result: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            result.add(node.module.split(".", 1)[0])
    return result


def _assignment_value(tree: ast.Module, name: str) -> object:
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            return ast.literal_eval(node.value)
    raise AssertionError(f"missing verifier assignment: {name}")


def main() -> None:
    verifier = VERIFIER.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    doc = DOC.read_text(encoding="utf-8")
    tree = ast.parse(verifier)

    bad = sorted(_imports(tree) & FORBIDDEN_IMPORTS)
    if bad:
        raise AssertionError(f"RUST-024 verifier imports network/process modules: {bad}")
    expected_assignments = {
        "UPSTREAM_URL": URL,
        "UPSTREAM_SHA256": SHA256,
        "ARCHIVE_ROOT": ARCHIVE_ROOT,
        "ARCHIVE_NAME": f"{ARCHIVE_ROOT}.tar.xz",
    }
    for name, expected in expected_assignments.items():
        actual = _assignment_value(tree, name)
        if actual != expected:
            raise AssertionError(f"verifier pin changed: {name}={actual!r} expected={expected!r}")
    for required in (
        "Rust distribution SHA-256 mismatch",
        "archive member outside pinned root",
        "duplicate archive member",
        "special archive member rejected",
        "archive link escapes pinned root",
        'filter="data"',
        "8/8 GREEN",
    ):
        if required not in verifier:
            raise AssertionError(f"missing fail-closed archive contract: {required}")
    print("[GREEN] RUST-024 verifier pins upstream URL/SHA semantically and rejects unsafe archive structures without network/process escape")

    if "permissions:\n  contents: read\n" not in workflow:
        raise AssertionError("workflow permissions must remain contents: read")
    for token in (URL, SHA256, IMAGE, RUSTC, CARGO):
        if token not in workflow:
            raise AssertionError(f"workflow pin missing: {token}")
    lower = workflow.lower()
    for forbidden in FORBIDDEN_WORKFLOW:
        if forbidden in lower:
            raise AssertionError(f"forbidden workflow privilege/publication path: {forbidden}")
    if workflow.count("curl ") != 1:
        raise AssertionError("workflow must have exactly one Rust distribution curl fetch")
    if 'curl --proto "=https" --tlsv1.2 --fail --location --silent --show-error' not in workflow:
        raise AssertionError("Rust distribution fetch must enforce HTTPS/TLS and fail closed")
    if "--network none" not in workflow:
        raise AssertionError("authenticated installer/consumer must run with Docker network disabled")
    print("[GREEN] workflow pins the upstream archive and immutable builder with least privilege and network-disabled execution")

    verify_pos = workflow.index("rust_024_upstream_rust_distribution.py verify-archive")
    extract_pos = workflow.index("rust_024_upstream_rust_distribution.py extract")
    install_pos = workflow.index("./install.sh")
    if not (verify_pos < extract_pos < install_pos):
        raise AssertionError("archive must be verified before extraction and installer execution")
    if workflow.count("rust_024_upstream_rust_distribution.py verify-archive") < 2:
        raise AssertionError("upstream archive must be reverified after toolchain consumption")
    for required in (
        "rust_023_rust_toolchain_closure.py collect",
        "rust_023_rust_toolchain_closure.py verify",
        ":/rust-toolchain:ro",
        "rustc --target x86_64-unknown-linux-gnu",
        "--disable-ldconfig",
    ):
        if required not in workflow:
            raise AssertionError(f"missing authenticated installation/closure boundary: {required}")
    if workflow.count("rust_023_rust_toolchain_closure.py verify") < 2:
        raise AssertionError("installed toolchain closure must be verified before and after isolated consumption")
    print("[GREEN] authenticated bytes are verified before execution, closed into RUST-023 identity, consumed read-only, and reverified")

    for required in (
        URL,
        SHA256,
        "does **not** yet replace the Rust toolchain used by the fully detached RUST-022",
        "RUST-025",
        "Production consensus remains Python-authoritative",
    ):
        if required not in doc:
            raise AssertionError(f"RUST-024 documentation boundary missing: {required}")
    print("[GREEN] documentation distinguishes upstream authentication from final Axven native-build consumption")

    for production_path in ('"axven/', '"p2p.py"', '"rpc.py"', '"wallet.py"', '"chain.py"', '"consensus.py"'):
        if production_path in workflow:
            raise AssertionError(f"workflow must not target production path: {production_path}")
    print("[GREEN] RUST-024 remains supply-chain CI only; production chain/routing/signing/publication stay untouched")

    print("RUST-024 upstream Rust distribution policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
