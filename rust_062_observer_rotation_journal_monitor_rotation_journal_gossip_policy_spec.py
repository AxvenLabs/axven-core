#!/usr/bin/env python3
"""RUST-062 static policy for TEST-ONLY monitor-rotation-journal checkpoint observation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-observer-rotation-journal-monitor-rotation-journal-gossip.yml"
VERIFIER = ROOT / "rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_verify.py"
SELFTEST = ROOT / "rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_selftest.py"
FIXTURE = ROOT / "rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_fixture.py"
BASE = ROOT / "rust_061_observer_rotation_journal_monitor_rotation_journal_verify.py"
DOC = ROOT / "RUST_062.md"
EXPECTED_RUST061_GIT_BLOB = "77027a4c3d5da9ec1e30d22c40edf74f2e5738be"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_060_multistep_observer_rotation_journal_monitor_rotation_verify",
    "rust_061_observer_rotation_journal_monitor_rotation_journal_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST061_GIT_BLOB
    assert (
        "import rust_061_observer_rotation_journal_monitor_rotation_journal_verify as journal_verify"
        in verifier
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-061 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print(
        "[GREEN] detached monitor-rotation-journal observer verifier/selftest "
        "have no signing or network capability"
    )

    for marker in (
        'BUNDLE_SCHEMA = "axven-native-observer-rotation-journal-monitor-set-rotation-journal-checkpoint-observation-bundle-v1"',
        'STATEMENT_SCHEMA = "axven-native-observer-rotation-journal-monitor-set-rotation-journal-checkpoint-observation-statement-v1"',
        'OBSERVATION_DOMAIN = b"AXVEN_NATIVE_OBSERVER_ROTATION_JOURNAL_MONITOR_SET_ROTATION_JOURNAL_CHECKPOINT_OBSERVATION_V1\\x00"',
        "THRESHOLD = 2",
        'OBSERVER_1_ID = "rust-062-test-only-monitor-rotation-journal-observer-1-v1"',
        'OBSERVER_2_ID = "rust-062-test-only-monitor-rotation-journal-observer-2-v1"',
        'OBSERVER_3_ID = "rust-062-test-only-monitor-rotation-journal-observer-3-v1"',
        'OBSERVER_1_PUBLIC_KEY = bytes.fromhex("fa4834147f6e690c3693eff61336046403cd8ae2a14f31b3c407358569239565")',
        'OBSERVER_2_PUBLIC_KEY = bytes.fromhex("2f0a7b29f53652005cd4720a3fe7acd08c85a4e29cd6f48d1905e276dac6ffef")',
        'OBSERVER_3_PUBLIC_KEY = bytes.fromhex("772c8a442b7db06e166cfbc1ccbcbcde6f3eba76a4e98ef3ffc519502237d6ef")',
        "observed cross-observer same-parent observer-rotation-journal monitor-rotation-journal checkpoint fork",
        "ids != sorted(ids)",
        "len(ids) != len(set(ids))",
    ):
        assert marker in verifier, marker
    checks += 1
    print(
        "[GREEN] 2-of-3 observer quorum, pins, ordering, and split-view rejection are fixed"
    )

    for marker in (
        "permissions:\n  contents: read",
        "persist-credentials: false",
        'python-version: "3.13.15"',
        "env -i",
        "/usr/bin/python3 -S",
        "chmod 0444 /tmp/axven-rust062-*.json",
        'test ! -e "$c/rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_fixture.py"',
    ):
        assert marker in workflow, marker
    for forbidden in (
        "id-token: write", "actions/upload-artifact", "attest", "release", "deploy"
    ):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, and non-publishing")

    for marker in (
        '"29" * 32', '"39" * 32', '"49" * 32', "Ed25519PrivateKey",
        "RUST-062 TEST-only monitor-rotation-journal observer public-key pin mismatch",
    ):
        assert marker in fixture, marker
    assert "rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_fixture.py" in workflow
    assert "rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_selftest.py" in workflow
    checks += 1
    print("[GREEN] deterministic observer private fixtures remain producer-side")

    for marker in (
        "at least 2-of-3",
        "same monitor-set sequence and same previous-checkpoint parent",
        "does **not** create global network gossip",
        "split-view safety over availability",
        "Production consensus remains Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] documentation preserves TEST-only observation boundary")

    assert checks == 6
    print(
        "RUST-062 monitor-rotation-journal observation static policy: "
        "6/6 checks passed"
    )


if __name__ == "__main__":
    main()
