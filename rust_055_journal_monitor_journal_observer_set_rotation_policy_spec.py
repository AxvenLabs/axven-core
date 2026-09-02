#!/usr/bin/env python3
"""RUST-055 static policy for TEST-ONLY journal-monitor-journal observer set rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-journal-monitor-journal-observer-set-rotation.yml"
VERIFIER = ROOT / "rust_055_journal_monitor_journal_observer_set_rotation_verify.py"
SELFTEST = ROOT / "rust_055_journal_monitor_journal_observer_set_rotation_selftest.py"
FIXTURE = ROOT / "rust_055_journal_monitor_journal_observer_set_rotation_fixture.py"
BASE = ROOT / "rust_054_journal_monitor_journal_gossip_verify.py"
DOC = ROOT / "RUST_055.md"
EXPECTED_RUST054_GIT_BLOB = "0b943090d4fdc0865e9a4848463cf4963b85c7fd"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_054_journal_monitor_journal_gossip_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_054_journal_monitor_journal_gossip_verify",
    "rust_055_journal_monitor_journal_observer_set_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST054_GIT_BLOB
    assert (
        "import rust_054_journal_monitor_journal_gossip_verify as gossip_verify"
        in verifier
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-054 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests",
        "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print(
        "[GREEN] detached RUST-055 verifier/selftest have no private signing "
        "or network capability"
    )

    for marker in (
        'ROTATION_SCHEMA = "axven-native-journal-monitor-journal-observer-set-rotation-v1"',
        'SUCCESSOR_BUNDLE_SCHEMA = "axven-native-journal-monitor-rotation-journal-checkpoint-observation-bundle-v2"',
        'ROTATION_DOMAIN = b"AXVEN_NATIVE_JOURNAL_MONITOR_JOURNAL_OBSERVER_SET_ROTATION_V1\\x00"',
        "THRESHOLD = 2",
        "NEW_SET_SEQUENCE = 1",
        'O4_ID = "rust-055-test-only-journal-monitor-journal-observer-4-v1"',
        'O4_PUBLIC_KEY = bytes.fromhex("c286554ac7959b2df1a97768b8c146a76d1fc528c34a14e648784a4ebc27ecef")',
        'raise AssertionError("predecessor observation bundle mismatch")',
        '"observed successor same-parent journal-monitor-rotation-journal checkpoint fork"',
        'ids != sorted(ids)',
        'len(ids) != len(set(ids))',
    ):
        assert marker in verifier, marker
    checks += 1
    print(
        "[GREEN] exact predecessor bundle, 2-of-3 rotation, revocation, "
        "ordering, and split-view contracts are fixed"
    )

    for marker in (
        "permissions:\n  contents: read",
        "persist-credentials: false",
        'python-version: "3.13.15"',
        "env -i",
        "/usr/bin/python3 -S",
        "chmod 0444 /tmp/axven-rust055-*.json",
        'test ! -e "$c/rust_055_journal_monitor_journal_observer_set_rotation_fixture.py"',
    ):
        assert marker in workflow, marker
    for forbidden in (
        "id-token: write", "actions/upload-artifact", "attest", "release", "deploy"
    ):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, and non-publishing")

    for marker in (
        '"9b" * 32', '"ab" * 32', '"bb" * 32', '"cb" * 32',
        "Ed25519PrivateKey",
        "RUST-055 TEST-only journal-monitor-journal observer public-key pin mismatch",
    ):
        assert marker in fixture, marker
    assert (
        "rust_055_journal_monitor_journal_observer_set_rotation_fixture.py"
        in workflow
    )
    assert (
        "rust_055_journal_monitor_journal_observer_set_rotation_selftest.py"
        in workflow
    )
    checks += 1
    print("[GREEN] deterministic private rotation fixtures remain producer-side")

    for marker in (
        "O1/O2/O3 -> O2/O3/O4",
        "exact RUST-054 observation-bundle SHA-256",
        "old RUST-054 v1 observation bundle cannot replay",
        "same monitor-set sequence and same previous-checkpoint parent",
        "Production consensus remains Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] documentation preserves TEST-only rotation and replay boundary")

    assert checks == 6
    print(
        "RUST-055 journal-monitor-journal observer rotation static policy: "
        "6/6 checks passed"
    )


if __name__ == "__main__":
    main()
