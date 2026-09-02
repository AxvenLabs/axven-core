#!/usr/bin/env python3
"""RUST-038 static policy for TEST-ONLY multi-observer checkpoint gossip."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-checkpoint-observer-gossip.yml"
VERIFIER = ROOT / "rust_038_checkpoint_gossip_verify.py"
SELFTEST = ROOT / "rust_038_checkpoint_gossip_selftest.py"
FIXTURE = ROOT / "rust_038_checkpoint_gossip_fixture.py"
BASE = ROOT / "rust_037_rotation_journal_verify.py"
DOC = ROOT / "RUST_038.md"
EXPECTED_RUST037_GIT_BLOB = "81e0e0c8749df7bbebfea79faaaa48266b74bf1c"
ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "json", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_037_rotation_journal_verify",
}
ALLOWED_SELFTEST_IMPORTS = ALLOWED_VERIFIER_IMPORTS | {
    "base64", "copy", "tempfile", "rust_038_checkpoint_gossip_verify",
}


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def blob(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()


def imported_roots(source: str) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def main() -> None:
    verifier = text(VERIFIER)
    selftest = text(SELFTEST)
    fixture = text(FIXTURE)
    workflow = text(WORKFLOW)
    doc = text(DOC)
    checks = 0

    assert blob(BASE.read_bytes()) == EXPECTED_RUST037_GIT_BLOB
    assert "import rust_037_rotation_journal_verify as journal_verify" in verifier
    checks += 1
    print("[GREEN] exact reviewed RUST-037 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib",
        "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached observer verifier/selftest have no signing or network capability")

    for marker in (
        'BUNDLE_SCHEMA = "axven-native-rotation-checkpoint-observation-bundle-v1"',
        'STATEMENT_SCHEMA = "axven-native-rotation-checkpoint-observation-statement-v1"',
        'OBSERVATION_DOMAIN = b"AXVEN_NATIVE_ROTATION_CHECKPOINT_OBSERVATION_V1\\x00"',
        "THRESHOLD = 2",
        'OBSERVER_1_ID = "rust-038-test-only-observer-1-v1"',
        'OBSERVER_2_ID = "rust-038-test-only-observer-2-v1"',
        'OBSERVER_3_ID = "rust-038-test-only-observer-3-v1"',
        'OBSERVER_1_PUBLIC_KEY = bytes.fromhex("c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242")',
        'OBSERVER_2_PUBLIC_KEY = bytes.fromhex("34b4d9043156cb6dcf0beb0a2949b7559c940d2bcb6dbe8c53a9b30278e3a746")',
        'OBSERVER_3_PUBLIC_KEY = bytes.fromhex("c853ad0f0cd2b619aea92ceec4fd56a24d6499d584ce79257e45cfd8139b60a7")',
        'raise AssertionError("observed cross-observer same-parent checkpoint fork")',
        'ids != sorted(ids)',
        'len(ids) != len(set(ids))',
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] 2-of-3 observer quorum, pins, ordering, and strict split-view rejection are fixed")

    for marker in (
        "permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"',
        "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust038-observer-bundle.json",
        "test ! -e \"$c/rust_038_checkpoint_gossip_fixture.py\"",
    ):
        assert marker in workflow, marker
    for forbidden in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, and non-publishing")

    for marker in (
        '"55" * 32', '"66" * 32', '"77" * 32', "Ed25519PrivateKey",
        "RUST-038 TEST-only observer public-key pin mismatch",
    ):
        assert marker in fixture, marker
    assert "rust_038_checkpoint_gossip_fixture.py" in workflow
    assert "rust_038_checkpoint_gossip_selftest.py" in workflow
    checks += 1
    print("[GREEN] deterministic observer private fixtures remain producer-side")

    for marker in (
        "at least 2-of-3", "same witness-set sequence and same previous-checkpoint parent",
        "does **not** create global network gossip", "strict fail-closed rule favors split-view safety over availability",
        "Production consensus remains Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] documentation preserves TEST-only gossip and availability boundary")

    assert checks == 6
    print("RUST-038 checkpoint gossip static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
