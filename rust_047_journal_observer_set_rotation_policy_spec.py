#!/usr/bin/env python3
"""RUST-047 static policy for TEST-ONLY journal-observer set rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-journal-observer-set-rotation.yml"
VERIFIER = ROOT / "rust_047_journal_observer_set_rotation_verify.py"
SELFTEST = ROOT / "rust_047_journal_observer_set_rotation_selftest.py"
FIXTURE = ROOT / "rust_047_journal_observer_set_rotation_fixture.py"
BASE = ROOT / "rust_046_monitor_journal_gossip_verify.py"
DOC = ROOT / "RUST_047.md"
EXPECTED_RUST046_GIT_BLOB = "804b8c13606bc509176be8fb6bf9aa7d9705dc8d"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_046_monitor_journal_gossip_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_046_monitor_journal_gossip_verify", "rust_047_journal_observer_set_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST046_GIT_BLOB
    assert "import rust_046_monitor_journal_gossip_verify as gossip_verify" in verifier
    checks += 1
    print("[GREEN] exact reviewed RUST-046 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib",
        "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached rotation verifier/selftest have no signing or network capability")

    for marker in (
        'ROTATION_SCHEMA = "axven-native-monitor-journal-observer-set-rotation-v1"',
        'SUCCESSOR_BUNDLE_SCHEMA = "axven-native-monitor-rotation-journal-checkpoint-observation-bundle-v2"',
        'ROTATION_DOMAIN = b"AXVEN_NATIVE_MONITOR_JOURNAL_OBSERVER_SET_ROTATION_V1\\x00"',
        "THRESHOLD = 2", "NEW_SET_SEQUENCE = 1",
        'J4_ID = "rust-047-test-only-journal-observer-4-v1"',
        'J4_PUBLIC_KEY = bytes.fromhex("3f0dda81e6abbcc5f17c359df8517177769d2dfff3d4ce942e7ce9a82dfb0db2")',
        'raise AssertionError("predecessor observation bundle mismatch")',
        'raise AssertionError("observed successor same-parent monitor-journal checkpoint fork")',
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] exact predecessor bundle, 2-of-3 rotation, revocation, and split-view contracts are fixed")

    for marker in (
        "permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"',
        "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust047-*.json",
        'test ! -e "$c/rust_047_journal_observer_set_rotation_fixture.py"',
    ):
        assert marker in workflow, marker
    for forbidden in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, and non-publishing")

    for marker in (
        '"0f" * 32', '"1f" * 32', '"2f" * 32', '"3f" * 32', "Ed25519PrivateKey",
        "RUST-047 TEST-only journal-observer public-key pin mismatch",
    ):
        assert marker in fixture, marker
    assert "rust_047_journal_observer_set_rotation_fixture.py" in workflow
    assert "rust_047_journal_observer_set_rotation_selftest.py" in workflow
    checks += 1
    print("[GREEN] deterministic private rotation fixtures remain producer-side")

    for marker in (
        "J1/J2/J3 to J2/J3/J4", "exact RUST-046 observation-bundle SHA-256",
        "old RUST-046 v1 observation bundle cannot replay", "same monitor-set sequence and same previous-checkpoint parent",
        "Production consensus remains Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] documentation preserves TEST-only rotation and replay boundary")

    assert checks == 6
    print("RUST-047 journal-observer rotation static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
