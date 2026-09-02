#!/usr/bin/env python3
"""RUST-034 static policy for the TEST-ONLY external-floor witness quorum."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-external-floor-witness-quorum.yml"
VERIFIER = ROOT / "rust_034_external_floor_witness_quorum_verify.py"
BASE = ROOT / "rust_033_external_floor_witness_verify.py"
DOC = ROOT / "RUST_034.md"
EXPECTED_RUST033_GIT_BLOB = "26d540d35be1beabab179906060c3a293ac53924"
ALLOWED_IMPORTS = {
    "__future__", "base64", "copy", "hashlib", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_033_external_floor_witness_verify",
}


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


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

    assert git_blob_sha(BASE.read_bytes()) == EXPECTED_RUST033_GIT_BLOB
    assert "import rust_033_external_floor_witness_verify as single_verify" in verifier
    assert "single_verify.WITNESS_KEY_ID: single_verify.WITNESS_PUBLIC_KEY" in verifier
    checks += 1
    print("[GREEN] RUST-034 includes the exact reviewed RUST-033 witness identity")

    roots = imported_roots(verifier)
    assert roots <= ALLOWED_IMPORTS, roots - ALLOWED_IMPORTS
    for forbidden in (
        "cryptography", "nacl", "OpenSSL", "Ed25519PrivateKey", "TEST_ONLY_WITNESS_SEED",
        ".sign(", "subprocess", "import axven", "from axven", "requests", "urllib", "socket",
    ):
        assert forbidden not in verifier, forbidden
    checks += 1
    print("[GREEN] detached quorum verifier contains no private signing or network capability")

    for marker in (
        'QUORUM_SCHEMA = "axven-native-external-floor-witness-quorum-v1"',
        "THRESHOLD = 2",
        'WITNESS_B_KEY_ID = "rust-034-test-only-floor-witness-b-v1"',
        'WITNESS_C_KEY_ID = "rust-034-test-only-floor-witness-c-v1"',
        'WITNESS_B_PUBLIC_KEY = bytes.fromhex("d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737")',
        'WITNESS_C_PUBLIC_KEY = bytes.fromhex("a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0")',
        'quorum.get("production") is not False',
        'key_ids != sorted(key_ids)',
        'len(set(key_ids)) != len(key_ids)',
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] 2-of-3 threshold, pinned keys, uniqueness and canonical ordering are fixed")

    for marker in (
        "permissions:\n  contents: read",
        "persist-credentials: false",
        "python-version: \"3.13.15\"",
        "env -i",
        "/usr/bin/python3 -S",
        'chmod 0444 "$floor" "$quorum"',
        'test ! -e "$consumer/external-floor.json"',
        'test ! -e "$consumer/floor-quorum.json"',
    ):
        assert marker in workflow, marker
    for forbidden in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays read-only, detached and non-publishing")

    for marker in (
        "0bcea6c25bf2e920391237f68a9ff4d36f3e8800521f93016ed2b4a10c81a09f",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "derived_public != quorum_verify.PINNED_WITNESSES[key_id]",
    ):
        assert marker in workflow, marker
    checks += 1
    print("[GREEN] deterministic private fixtures stay producer-side and must match verifier pins")

    for marker in (
        "TEST-ONLY 2-of-3",
        "does **not** make the witness producers operationally independent",
        "production decisions remain explicit future approval gates",
        "Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] documentation preserves the non-production security boundary")

    assert checks == 6
    print("RUST-034 witness quorum static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
