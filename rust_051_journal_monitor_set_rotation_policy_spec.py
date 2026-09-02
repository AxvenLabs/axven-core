#!/usr/bin/env python3
"""RUST-051 static policy for TEST-ONLY journal-monitor set rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-journal-monitor-set-rotation.yml"
VERIFIER = ROOT / "rust_051_journal_monitor_set_rotation_verify.py"
SELFTEST = ROOT / "rust_051_journal_monitor_set_rotation_selftest.py"
FIXTURE = ROOT / "rust_051_journal_monitor_set_rotation_fixture.py"
BASE = ROOT / "rust_050_journal_observer_journal_monitor_verify.py"
DOC = ROOT / "RUST_051.md"
EXPECTED_RUST050_GIT_BLOB = "d3d518c4832bc22570e8cfa6f17796bb6efbcd06"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_050_journal_observer_journal_monitor_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_050_journal_observer_journal_monitor_verify", "rust_051_journal_monitor_set_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST050_GIT_BLOB
    assert "import rust_050_journal_observer_journal_monitor_verify as monitor_verify" in verifier
    checks += 1
    print("[GREEN] exact reviewed RUST-050 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib",
        "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-051 verifier/selftest have no private signing or network capability")

    for marker in (
        'ROTATION_SCHEMA = "axven-native-journal-observer-journal-monitor-set-rotation-v1"',
        'SUCCESSOR_BUNDLE_SCHEMA = "axven-native-journal-observer-journal-checkpoint-monitor-bundle-v2"',
        'ROTATION_DOMAIN = b"AXVEN_NATIVE_JOURNAL_OBSERVER_JOURNAL_MONITOR_SET_ROTATION_V1\\x00"',
        "THRESHOLD = 2", "NEW_SET_SEQUENCE = 1",
        'JM4_ID = "rust-051-test-only-journal-monitor-4-v1"',
        'JM4_PUBLIC_KEY = bytes.fromhex("fd1503f19f59731c16f1dfcee91d27a416ff024b3cac4ae319362d5e3df7dbca")',
        'raise AssertionError("predecessor monitor bundle mismatch")',
        'raise AssertionError("observed successor same-parent journal-observer-journal checkpoint fork")',
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] exact predecessor bundle, 2-of-3 rotation, revocation, and split-view contracts are fixed")

    for marker in (
        "permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"',
        "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust051-*.json",
        'test ! -e "$c/rust_051_journal_monitor_set_rotation_fixture.py"',
    ):
        assert marker in workflow, marker
    for forbidden in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, and non-publishing")

    for marker in (
        '"5a" * 32', '"6a" * 32', '"7a" * 32', '"8a" * 32', "Ed25519PrivateKey",
        "RUST-051 TEST-only journal-monitor public-key pin mismatch",
    ):
        assert marker in fixture, marker
    assert "rust_051_journal_monitor_set_rotation_fixture.py" in workflow
    assert "rust_051_journal_monitor_set_rotation_selftest.py" in workflow
    checks += 1
    print("[GREEN] deterministic private rotation fixtures remain producer-side")

    for marker in (
        "JM1/JM2/JM3` to `JM2/JM3/JM4", "exact RUST-050 monitor-bundle SHA-256",
        "old RUST-050 v1 monitor bundle cannot replay", "same observer-set sequence and same previous-checkpoint parent",
        "Production consensus remains Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] documentation preserves TEST-only rotation and replay boundary")

    assert checks == 6
    print("RUST-051 journal-monitor rotation static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
