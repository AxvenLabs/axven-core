#!/usr/bin/env python3
"""RUST-056 static policy for TEST-ONLY multi-step journal-monitor-journal observer rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-multistep-journal-monitor-journal-observer-rotation.yml"
VERIFIER = ROOT / "rust_056_multistep_journal_monitor_journal_observer_rotation_verify.py"
SELFTEST = ROOT / "rust_056_multistep_journal_monitor_journal_observer_rotation_selftest.py"
FIXTURE = ROOT / "rust_056_multistep_journal_monitor_journal_observer_rotation_fixture.py"
BASE = ROOT / "rust_055_journal_monitor_journal_observer_set_rotation_verify.py"
DOC = ROOT / "RUST_056.md"
EXPECTED_RUST055_GIT_BLOB = "06c20a4e37eab5b533936c7f7aefce742e634068"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_054_journal_monitor_journal_gossip_verify",
    "rust_055_journal_monitor_journal_observer_set_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_054_journal_monitor_journal_gossip_verify",
    "rust_056_multistep_journal_monitor_journal_observer_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST055_GIT_BLOB
    assert (
        "import rust_055_journal_monitor_journal_observer_set_rotation_verify as rotation1_verify"
        in verifier
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-055 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib",
        "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached multi-step verifier/selftest have no signing or network capability")

    for marker in (
        'ROTATION_SCHEMA = "axven-native-journal-monitor-journal-observer-set-rotation-v2"',
        'FINAL_BUNDLE_SCHEMA = "axven-native-journal-monitor-rotation-journal-checkpoint-observation-bundle-v3"',
        'ROTATION_DOMAIN = b"AXVEN_NATIVE_JOURNAL_MONITOR_JOURNAL_OBSERVER_SET_ROTATION_V2\\x00"',
        "THRESHOLD = 2",
        "FINAL_SET_SEQUENCE = 2",
        'O5_ID = "rust-056-test-only-journal-monitor-journal-observer-5-v1"',
        'O5_PUBLIC_KEY = bytes.fromhex("3a1c28c339928a98cd829c08db30e7676864abbc6213c41ebec38f884e49e23b")',
        'raise AssertionError("predecessor journal-monitor-journal observer rotation authorization digest mismatch")',
        "observed final same-parent journal-monitor-rotation-journal checkpoint fork",
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] second rotation, cumulative revocation, predecessor digests, and split-view rejection are fixed")

    for marker in (
        "permissions:\n  contents: read",
        "persist-credentials: false",
        'python-version: "3.13.15"',
        "env -i",
        "/usr/bin/python3 -S",
        "chmod 0444 /tmp/axven-rust056-*.json",
        'test ! -e "$c/rust_056_multistep_journal_monitor_journal_observer_rotation_fixture.py"',
    ):
        assert marker in workflow, marker
    for forbidden in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, and non-publishing")

    for marker in (
        '"ab" * 32', '"bb" * 32', '"cb" * 32', '"db" * 32',
        "Ed25519PrivateKey",
        "RUST-056 TEST-only journal-monitor-journal observer public-key pin mismatch",
    ):
        assert marker in fixture, marker
    assert "rust_056_multistep_journal_monitor_journal_observer_rotation_fixture.py" in workflow
    assert "rust_056_multistep_journal_monitor_journal_observer_rotation_selftest.py" in workflow
    checks += 1
    print("[GREEN] deterministic private second-rotation fixtures remain producer-side")

    for marker in (
        "O1/O2/O3 -> O2/O3/O4 -> O3/O4/O5",
        "exact RUST-055 first-rotation authorization SHA-256",
        "RUST-055 v2 successor bundle cannot replay",
        "same monitor-set sequence and same previous-checkpoint parent",
        "Production consensus remains Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] documentation preserves TEST-only multi-step rotation and replay boundary")

    assert checks == 6
    print("RUST-056 multi-step journal-monitor-journal observer rotation static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
