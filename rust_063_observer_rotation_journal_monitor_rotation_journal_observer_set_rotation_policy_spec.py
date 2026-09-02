#!/usr/bin/env python3
"""RUST-063 static policy for TEST-ONLY monitor-rotation-journal observer-set rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-observer-rotation-journal-monitor-rotation-journal-observer-set-rotation.yml"
VERIFIER = ROOT / "rust_063_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify.py"
SELFTEST = ROOT / "rust_063_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_selftest.py"
FIXTURE = ROOT / "rust_063_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_fixture.py"
BASE = ROOT / "rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_verify.py"
DOC = ROOT / "RUST_063.md"
EXPECTED_RUST062_GIT_BLOB = "5b8fbd6d8c6f5f0cffc39df4fee677cb0d7efe95"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_verify",
    "rust_063_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify",
}


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def blob(raw: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(raw)}\0".encode("ascii") + raw
    ).hexdigest()


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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST062_GIT_BLOB
    assert (
        "import rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_verify as gossip_verify"
        in verifier
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-062 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print(
        "[GREEN] detached monitor-rotation-journal observer rotation verifier/selftest "
        "have no signing or network capability"
    )

    for marker in (
        'OBSERVER_SET_SCHEMA = "axven-native-observer-rotation-journal-monitor-set-rotation-journal-observer-set-v1"',
        'ROTATION_SCHEMA = "axven-native-observer-rotation-journal-monitor-set-rotation-journal-observer-set-rotation-v1"',
        'SUCCESSOR_BUNDLE_SCHEMA = "axven-native-observer-rotation-journal-monitor-set-rotation-journal-checkpoint-observation-bundle-v2"',
        'ROTATION_DOMAIN = b"AXVEN_NATIVE_OBSERVER_ROTATION_JOURNAL_MONITOR_SET_ROTATION_JOURNAL_OBSERVER_SET_ROTATION_V1\\x00"',
        "THRESHOLD = 2",
        "OLD_SET_SEQUENCE = 0",
        "NEW_SET_SEQUENCE = 1",
        'O4_ID = "rust-063-test-only-monitor-rotation-journal-observer-4-v1"',
        'O4_PUBLIC_KEY = bytes.fromhex("ab7260f20edab8208990343f0b9954b20b42b0bd81c8256bebab0c70d41750cc")',
        "REVOKED_OBSERVER_ID = gossip_verify.OBSERVER_1_ID",
        '"predecessor_observation_bundle_sha256"',
        '"checkpoint_statement_sha256"',
        "revoked monitor-rotation-journal observer resurrected",
    ):
        assert marker in verifier, marker
    checks += 1
    print(
        "[GREEN] 2-of-3 predecessor authorization, O1 revocation, "
        "O2/O3/O4 successor pins, and exact checkpoint bindings are fixed"
    )

    for marker in (
        "3/3 valid two-observer subsets accepted",
        "old-rust062-bundle-replay",
        "observed-valid-successor-same-parent-fork",
        "successor-observed-target",
        "successor-statement-production",
        "40/40 expected cases passed",
    ):
        assert marker in selftest, marker
    checks += 1
    print("[GREEN] availability, replay, inherited-target, and split-view failures are covered")

    for marker in (
        "permissions:\n  contents: read",
        "persist-credentials: false",
        'python-version: "3.13.15"',
        "env -i",
        "/usr/bin/python3 -S",
        "chmod 0444 /tmp/axven-rust063-*.json",
        'test ! -e "$c/rust_063_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_fixture.py"',
    ):
        assert marker in workflow, marker
    for forbidden in (
        "id-token: write", "actions/upload-artifact", "attest", "release", "deploy"
    ):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, and non-publishing")

    for marker in (
        '"29" * 32', '"39" * 32', '"49" * 32', '"59" * 32',
        "Ed25519PrivateKey",
        "RUST-063 TEST-only monitor-rotation-journal observer public-key pin mismatch",
    ):
        assert marker in fixture, marker
    for marker in (
        "O1 is revoked",
        "O1/O2/O3 -> O2/O3/O4",
        "exact RUST-062 predecessor observation bundle",
        "split-view safety over availability",
        "Production consensus remains Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] deterministic producer keys and TEST-only documentation boundary are preserved")

    assert checks == 6
    print(
        "RUST-063 monitor-rotation-journal observer-set rotation static policy: "
        "6/6 checks passed"
    )


if __name__ == "__main__":
    main()
