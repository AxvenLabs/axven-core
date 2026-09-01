#!/usr/bin/env python3
"""RUST-032 static policy for the TEST-ONLY external monotonic-floor interface."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-external-monotonic-floor.yml"
VERIFIER = ROOT / "rust_032_external_monotonic_floor_verify.py"
BASE = ROOT / "rust_031_stdlib_trust_state_material_verify.py"
DOC = ROOT / "RUST_032.md"
EXPECTED_RUST031_GIT_BLOB = "984961a2c84967fc0ab0bfdc119971ba1fa3e003"
ALLOWED_IMPORTS = {
    "__future__", "copy", "hashlib", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_031_stdlib_trust_state_material_verify",
}


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def imported_roots(source: str) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def git_blob_sha(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()


def main() -> None:
    checks = 0
    verifier = text(VERIFIER)
    workflow = text(WORKFLOW)
    doc = text(DOC)

    assert git_blob_sha(BASE.read_bytes()) == EXPECTED_RUST031_GIT_BLOB
    assert "import rust_031_stdlib_trust_state_material_verify as trust_verify" in verifier
    checks += 1
    print("[GREEN] RUST-032 composes the exact reviewed RUST-031 verifier without modifying it")

    roots = imported_roots(verifier)
    assert roots <= ALLOWED_IMPORTS, roots - ALLOWED_IMPORTS
    for forbidden in (
        "cryptography", "nacl", "OpenSSL", "Ed25519PrivateKey", "TEST_SEED",
        "def seal", "def issue", "subprocess", "import axven", "from axven",
        "requests", "urllib", "socket",
    ):
        assert forbidden not in verifier, forbidden
    checks += 1
    print("[GREEN] detached floor wrapper is stdlib-only plus pinned RUST-030/RUST-031 verification modules")

    for marker in (
        'EXTERNAL_FLOOR_SCHEMA = "axven-native-external-monotonic-floor-v1"',
        'EXTERNAL_PROVIDER = "test-only-monotonic-floor-simulator"',
        'value["sequence"] != trust_verify.MINIMUM_SEQUENCE',
        'value.get("key_id") != trust_verify.NEW_KEY_ID',
        'value.get("public_key") != trust_verify.NEW_PUBLIC_KEY.hex()',
        "sequence < required_floor",
        'final_state["sequence"] < sequence',
        'floor.get("state_sha256") != hashlib.sha256(final_raw).hexdigest()',
        "11/11 expected cases passed",
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] external runtime floor and exact accepted-state binding fail closed")

    for marker in (
        "floor=/tmp/axven-rust032-external-floor.json",
        'chmod 0444 "$floor"',
        'test ! -e "$consumer/external-floor.json"',
        "/usr/bin/python3 -S",
        "env -i",
        "PYTHONNOUSERSITE=1",
        "rust_032_external_monotonic_floor_verify.py verify",
        "rust_032_external_monotonic_floor_verify.py selftest",
    ):
        assert marker in workflow, marker
    checks += 1
    print("[GREEN] floor evidence stays outside the detached consumer and is read-only in the TEST-ONLY simulation")

    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    lower = workflow.lower()
    for forbidden in (
        "id-token: write", "attestations: write", "packages: write", "contents: write",
        "actions/upload-artifact", "actions/attest", "maturin publish", "twine upload",
        "gh release", "docker push",
    ):
        assert forbidden not in lower, forbidden
    checks += 1
    print("[GREEN] RUST-032 adds no publication, OIDC, signing, release or deployment privilege")

    lower_doc = doc.lower()
    for marker in (
        "test-only external-floor interface simulation",
        "does not claim to solve production rollback resistance",
        "separate explicit design and approval gate",
        "production consensus remains python-authoritative",
    ):
        assert marker in lower_doc, marker
    checks += 1
    print("[GREEN] production anti-rollback and Rust routing remain explicit future approval gates")

    assert checks == 6
    print("RUST-032 external monotonic floor policy contract: 6/6 GREEN")


if __name__ == "__main__":
    main()
