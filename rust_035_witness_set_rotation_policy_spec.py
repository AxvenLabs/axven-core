#!/usr/bin/env python3
"""RUST-035 static policy for TEST-ONLY witness-set rotation continuity."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-witness-set-rotation.yml"
VERIFIER = ROOT / "rust_035_witness_set_rotation_verify.py"
BASE = ROOT / "rust_034_external_floor_witness_quorum_verify.py"
DOC = ROOT / "RUST_035.md"
EXPECTED_RUST034_GIT_BLOB = "11b8f9b8fca6a475e99eb44af6c616eb1ec9cc57"
ALLOWED_IMPORTS = {
    "__future__", "base64", "copy", "hashlib", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_034_external_floor_witness_quorum_verify",
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

    assert git_blob_sha(BASE.read_bytes()) == EXPECTED_RUST034_GIT_BLOB
    assert "import rust_034_external_floor_witness_quorum_verify as quorum_verify" in verifier
    assert "OLD_PINNED_WITNESSES = dict(quorum_verify.PINNED_WITNESSES)" in verifier
    checks += 1
    print("[GREEN] RUST-035 composes the exact reviewed RUST-034 witness set")

    roots = imported_roots(verifier)
    assert roots <= ALLOWED_IMPORTS, roots - ALLOWED_IMPORTS
    for forbidden in (
        "cryptography", "nacl", "OpenSSL", "Ed25519PrivateKey", "TEST_ONLY_SEEDS",
        ".sign(", "subprocess", "import axven", "from axven", "requests", "urllib", "socket",
    ):
        assert forbidden not in verifier, forbidden
    checks += 1
    print("[GREEN] detached rotation verifier contains no private signing or network capability")

    for marker in (
        'ROTATION_SCHEMA = "axven-native-external-floor-witness-set-rotation-v1"',
        'SUCCESSOR_QUORUM_SCHEMA = "axven-native-external-floor-witness-quorum-v2"',
        "OLD_SET_SEQUENCE = 0",
        "NEW_SET_SEQUENCE = 1",
        'D_KEY_ID = "rust-035-test-only-floor-witness-d-v1"',
        'D_PUBLIC_KEY = bytes.fromhex("17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce")',
        "REVOKED_KEY_ID = quorum_verify.single_verify.WITNESS_KEY_ID",
        'rotation.get("revoked_key_ids") != [REVOKED_KEY_ID]',
        'successor.get("set_sequence")',
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] fixed A/B/C -> B/C/D rotation, revocation, and set epoch are pinned")

    for marker in (
        "permissions:\n  contents: read",
        "persist-credentials: false",
        "python-version: \"3.13.15\"",
        "env -i",
        "/usr/bin/python3 -S",
        'chmod 0444 "$floor" "$rotation" "$rotation_auth" "$successor"',
        'test ! -e "$consumer/witness-set-rotation.json"',
        'test ! -e "$consumer/rotation-auth.json"',
        'test ! -e "$consumer/successor-quorum.json"',
    ):
        assert marker in workflow, marker
    for forbidden in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays read-only, detached, and non-publishing")

    for marker in (
        "0bcea6c25bf2e920391237f68a9ff4d36f3e8800521f93016ed2b4a10c81a09f",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "derived_public != pins[key_id]",
    ):
        assert marker in workflow, marker
    checks += 1
    print("[GREEN] predecessor and successor TEST private fixtures stay producer-side and match verifier pins")

    for marker in (
        "A/B/C",
        "B/C/D",
        "explicitly revokes witness `A`",
        "old RUST-034 quorum schema is deliberately not accepted",
        "Production consensus remains Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] documentation preserves rotation/revocation semantics and non-production boundary")

    assert checks == 6
    print("RUST-035 witness-set rotation static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
