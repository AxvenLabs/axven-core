#!/usr/bin/env python3
"""RUST-065 static policy for TEST-ONLY monitor-rotation-journal observer rotation journal continuity."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal-observer-rotation-journal.yml"
VERIFIER = ROOT / "rust_065_monitor_rotation_journal_observer_rotation_journal_verify.py"
SELFTEST = ROOT / "rust_065_monitor_rotation_journal_observer_rotation_journal_selftest.py"
FIXTURE = ROOT / "rust_065_monitor_rotation_journal_observer_rotation_journal_fixture.py"
BASE = ROOT / "rust_064_multistep_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify.py"
DOC = ROOT / "RUST_065.md"
EXPECTED_RUST064_GIT_BLOB = "5479196bcfb49fe845245d82428e70ddb6fbde32"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_verify",
    "rust_063_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify",
    "rust_064_multistep_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_065_monitor_rotation_journal_observer_rotation_journal_verify",
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
    verifier = text(VERIFIER); selftest = text(SELFTEST); fixture = text(FIXTURE)
    workflow = text(WORKFLOW); doc = text(DOC); checks = 0

    assert blob(BASE.read_bytes()) == EXPECTED_RUST064_GIT_BLOB
    assert (
        "import rust_064_multistep_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify as rotation2_verify"
        in verifier
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-064 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests",
        "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-065 verifier/selftest have no signing or network capability")

    for marker in (
        'JOURNAL_SCHEMA = "axven-native-observer-rotation-journal-monitor-set-rotation-journal-observer-set-rotation-journal-v1"',
        'CHECKPOINT_DOMAIN = b"AXVEN_NATIVE_OBSERVER_ROTATION_JOURNAL_MONITOR_SET_ROTATION_JOURNAL_OBSERVER_SET_ROTATION_JOURNAL_CHECKPOINT_V1\\x00"',
        "THRESHOLD = 2",
        '"rotation_auth_sha256"',
        '"monitor_rotation_journal_checkpoint_sha256"',
        '"observed_target_sha256"',
        'raise AssertionError(\n            "observed same-parent monitor-rotation-journal observer-rotation-journal checkpoint fork"',
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] append-only journal, exact target bindings, 2-of-3 checkpoints, and fork rejection are fixed")

    for marker in (
        "permissions:\n  contents: read", "persist-credentials: false",
        'python-version: "3.13.15"', "env -i", "/usr/bin/python3 -S",
        "chmod 0444", "axven-rust065",
        'test ! -e "$c/rust_065_monitor_rotation_journal_observer_rotation_journal_fixture.py"',
    ):
        assert marker in workflow, marker
    for forbidden in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, and non-publishing")

    for marker in (
        '"39" * 32', '"49" * 32', '"59" * 32', '"69" * 32',
        "Ed25519PrivateKey",
        "RUST-065 TEST-only monitor-rotation-journal observer journal public-key pin mismatch",
    ):
        assert marker in fixture, marker
    assert "rust_065_monitor_rotation_journal_observer_rotation_journal_fixture.py" in workflow
    assert "rust_065_monitor_rotation_journal_observer_rotation_journal_selftest.py" in workflow
    checks += 1
    print("[GREEN] deterministic observer checkpoint private fixtures remain producer-side")

    for marker in (
        "O1/O2/O3 -> O2/O3/O4 -> O3/O4/O5",
        "exact RUST-061 final monitor-rotation-journal checkpoint SHA-256",
        "cumulative revocation `[O1, O2]`",
        "same-parent final monitor-rotation-journal observer-rotation-journal checkpoint fork",
        "Production consensus remains Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] documentation preserves TEST-only journal and inherited target boundary")

    assert checks == 6
    print("RUST-065 monitor-rotation-journal observer rotation journal static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
