#!/usr/bin/env python3
"""RUST-033 static policy for the TEST-ONLY signed external-floor witness."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-signed-external-floor-witness.yml"
VERIFIER = ROOT / "rust_033_external_floor_witness_verify.py"
BASE = ROOT / "rust_032_external_monotonic_floor_verify.py"
DOC = ROOT / "RUST_033.md"
EXPECTED_RUST032_GIT_BLOB = "bbaf30dba13689347ff615d5eaca9573d45cdda3"
ALLOWED_IMPORTS = {
    "__future__", "base64", "copy", "hashlib", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
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

    assert git_blob_sha(BASE.read_bytes()) == EXPECTED_RUST032_GIT_BLOB
    assert "import rust_032_external_monotonic_floor_verify as floor_verify" in verifier
    checks += 1
    print("[GREEN] RUST-033 composes the exact reviewed RUST-032 external-floor verifier")

    roots = imported_roots(verifier)
    assert roots <= ALLOWED_IMPORTS, roots - ALLOWED_IMPORTS
    for forbidden in (
        "cryptography", "nacl", "OpenSSL", "Ed25519PrivateKey", "TEST_ONLY_WITNESS_SEED",
        "private.sign(", "def seal", "def issue", "subprocess", "import axven", "from axven",
        "requests", "urllib", "socket",
    ):
        assert forbidden not in verifier, forbidden
    checks += 1
    print("[GREEN] detached witness verifier contains no producer/private-key capability")

    for marker in (
        'WITNESS_ENVELOPE_SCHEMA = "axven-native-external-floor-witness-envelope-v1"',
        'WITNESS_PAYLOAD_TYPE = "application/vnd.axven.native-external-monotonic-floor.v1+json"',
        'WITNESS_KEY_ID = "rust-033-test-only-floor-witness-v1"',
        'WITNESS_PUBLIC_KEY = bytes.fromhex("2dc9daf238e33ee76362715bf7b37a2d3e7472b83c24242fa4d0e914f1324588")',
        'WITNESS_DOMAIN = b"AXVEN_NATIVE_EXTERNAL_FLOOR_WITNESS_V1\\x00"',
        "material_verify.ed25519_verify(",
        "11/11 expected cases passed",
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] witness identity, domain and public key are independently pinned")

    for marker in (
        "requirements-ci-runtime-posix.lock",
        "Ed25519PrivateKey.from_private_bytes",
        "0bcea6c25bf2e920391237f68a9ff4d36f3e8800521f93016ed2b4a10c81a09f",
        'chmod 0444 "$floor" "$witness"',
        'test ! -e "$consumer/external-floor.json"',
        'test ! -e "$consumer/floor-witness.json"',
        "/usr/bin/python3 -S",
        "env -i",
        "PYTHONNOUSERSITE=1",
        "rust_033_external_floor_witness_verify.py selftest",
    ):
        assert marker in workflow, marker
    checks += 1
    print("[GREEN] TEST-ONLY signing remains producer-side and external evidence stays outside detached consumer")

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
    print("[GREEN] RUST-033 adds no publication, OIDC, release or deployment privilege")

    lower_doc = doc.lower()
    for marker in (
        "test-only signed external-floor witness",
        "does not provide durable rollback resistance",
        "separate explicit design and approval gates",
        "production consensus remains python-authoritative",
    ):
        assert marker in lower_doc, marker
    checks += 1
    print("[GREEN] production witness/custody/rollback resistance remain explicit future gates")

    assert checks == 6
    print("RUST-033 signed external floor witness policy contract: 6/6 GREEN")


if __name__ == "__main__":
    main()
