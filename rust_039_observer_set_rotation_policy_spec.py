#!/usr/bin/env python3
"""RUST-039 static policy for TEST-ONLY observer-set rotation continuity."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-observer-set-rotation.yml"
VERIFIER = ROOT / "rust_039_observer_set_rotation_verify.py"
SELFTEST = ROOT / "rust_039_observer_set_rotation_selftest.py"
FIXTURE = ROOT / "rust_039_observer_set_rotation_fixture.py"
BASE = ROOT / "rust_038_checkpoint_gossip_verify.py"
DOC = ROOT / "RUST_039.md"
EXPECTED_RUST038_GIT_BLOB = "7ca8ed0ea420432915c5c9b82fad24e81fc15029"
ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_037_rotation_journal_verify", "rust_038_checkpoint_gossip_verify",
}
ALLOWED_SELFTEST_IMPORTS = ALLOWED_VERIFIER_IMPORTS | {
    "base64", "copy", "json", "tempfile", "rust_039_observer_set_rotation_verify",
}


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def blob(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()


def roots(source: str) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            result.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            result.add(node.module.split(".", 1)[0])
    return result


def main() -> None:
    verifier = text(VERIFIER)
    selftest = text(SELFTEST)
    fixture = text(FIXTURE)
    workflow = text(WORKFLOW)
    doc = text(DOC)
    checks = 0

    assert blob(BASE.read_bytes()) == EXPECTED_RUST038_GIT_BLOB
    assert "import rust_038_checkpoint_gossip_verify as gossip_verify" in verifier
    checks += 1
    print("[GREEN] exact reviewed RUST-038 verifier is composed")

    assert roots(verifier) <= ALLOWED_VERIFIER_IMPORTS, roots(verifier) - ALLOWED_VERIFIER_IMPORTS
    assert roots(selftest) <= ALLOWED_SELFTEST_IMPORTS, roots(selftest) - ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib",
        "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached observer-set verifier/selftest have no private signing or network capability")

    for marker in (
        'OBSERVER_SET_SCHEMA = "axven-native-checkpoint-observer-set-v1"',
        'ROTATION_SCHEMA = "axven-native-checkpoint-observer-set-rotation-v1"',
        'SUCCESSOR_BUNDLE_SCHEMA = "axven-native-rotation-checkpoint-observation-bundle-v2"',
        'ROTATION_DOMAIN = b"AXVEN_NATIVE_CHECKPOINT_OBSERVER_SET_ROTATION_V1\\x00"',
        'SUCCESSOR_DOMAIN = b"AXVEN_NATIVE_ROTATION_CHECKPOINT_OBSERVATION_V2\\x00"',
        "THRESHOLD = 2", "OLD_SET_SEQUENCE = 0", "NEW_SET_SEQUENCE = 1",
        'O4_ID = "rust-039-test-only-observer-4-v1"',
        'O4_PUBLIC_KEY = bytes.fromhex("b2491d9502ae28630a2bacb2e0c74510ffcdd328c334ff3e1393e75b2d31e7dc")',
        "REVOKED_OBSERVER_ID = gossip_verify.OBSERVER_1_ID",
        'raise AssertionError("observed successor same-parent checkpoint fork")',
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] O1 revocation, O2/O3/O4 successor set, epoch binding and split-view rejection are pinned")

    for marker in (
        "permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"',
        "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust039-observer-set-rotation.json",
        'test ! -e "$c/rust_039_observer_set_rotation_fixture.py"',
    ):
        assert marker in workflow, marker
    for forbidden in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only and non-publishing")

    for marker in (
        '"55" * 32', '"66" * 32', '"77" * 32', '"88" * 32', "Ed25519PrivateKey",
        "RUST-039 TEST-only observer public-key pin mismatch",
    ):
        assert marker in fixture, marker
    assert "rust_039_observer_set_rotation_fixture.py" in workflow
    assert "rust_039_observer_set_rotation_selftest.py" in workflow
    checks += 1
    print("[GREEN] deterministic predecessor/successor private fixtures remain producer-side")

    for marker in (
        "O1/O2/O3` to `O2/O3/O4", "O1 explicitly revoked", "old RUST-038 bundle replay",
        "does **not** create independent observer administration", "Production consensus remains Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] documentation preserves TEST-only observer-rotation boundary")

    assert checks == 6
    print("RUST-039 observer-set rotation static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
