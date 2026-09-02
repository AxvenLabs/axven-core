#!/usr/bin/env python3
"""RUST-059 static policy for TEST-ONLY observer-rotation-journal monitor rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-journal-monitor-journal-observer-rotation-journal-monitor-set-rotation.yml"
VERIFIER = ROOT / "rust_059_observer_rotation_journal_monitor_set_rotation_verify.py"
SELFTEST = ROOT / "rust_059_observer_rotation_journal_monitor_set_rotation_selftest.py"
FIXTURE = ROOT / "rust_059_observer_rotation_journal_monitor_set_rotation_fixture.py"
BASE = ROOT / "rust_058_observer_rotation_journal_monitor_verify.py"
DOC = ROOT / "RUST_059.md"
EXPECTED_RUST058_GIT_BLOB = "7575d5c8a45900e87711ac3d64cf2c9f088e8bfc"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_058_observer_rotation_journal_monitor_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_058_observer_rotation_journal_monitor_verify",
    "rust_059_observer_rotation_journal_monitor_set_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST058_GIT_BLOB
    assert "import rust_058_observer_rotation_journal_monitor_verify as monitor_verify" in verifier
    checks += 1
    print("[GREEN] exact reviewed RUST-058 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib",
        "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-059 verifier/selftest have no signing or network capability")

    for marker in (
        'ROTATION_SCHEMA = "axven-native-journal-monitor-journal-observer-rotation-journal-monitor-set-rotation-v1"',
        'SUCCESSOR_BUNDLE_SCHEMA = "axven-native-journal-monitor-journal-observer-rotation-journal-checkpoint-monitor-bundle-v2"',
        "THRESHOLD = 2", "NEW_SET_SEQUENCE = 1",
        'M4_ID = "rust-059-test-only-observer-rotation-journal-monitor-4-v1"',
        'M4_PUBLIC_KEY = bytes.fromhex("fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618")',
        'raise AssertionError("predecessor observer-rotation-journal monitor bundle mismatch")',
        'raise AssertionError("observed successor same-parent observer-rotation-journal checkpoint fork")',
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] exact predecessor bundle, 2-of-3 rotation, revocation and split-view contracts are pinned")

    for marker in (
        "permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"',
        "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust059-*.json",
        'test ! -e "$c/rust_059_observer_rotation_journal_monitor_set_rotation_fixture.py"',
    ):
        assert marker in workflow, marker
    for forbidden in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only and non-publishing")

    for marker in (
        '"d8" * 32', '"e8" * 32', '"f8" * 32', '"09" * 32', "Ed25519PrivateKey",
        "RUST-059 TEST-only monitor public-key pin mismatch",
    ):
        assert marker in fixture, marker
    assert "3/3 valid two-monitor subsets accepted" in selftest
    assert "old-rust058-bundle-replay" in selftest
    checks += 1
    print("[GREEN] availability, replay rejection and producer-only private keys are pinned")

    for marker in (
        "M1/M2/M3 -> M2/M3/M4", "exact RUST-058 predecessor monitor-bundle SHA-256",
        "old RUST-058 v1 monitor bundle cannot replay", "same observer-set sequence and same previous-checkpoint parent",
        "Production consensus remains Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] documentation preserves TEST-only monitor rotation boundary")

    assert checks == 6
    print("RUST-059 observer-rotation-journal monitor rotation static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
