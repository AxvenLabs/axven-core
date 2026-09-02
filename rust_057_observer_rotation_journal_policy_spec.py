#!/usr/bin/env python3
"""RUST-057 static policy for TEST-ONLY observer rotation journal continuity."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-journal-monitor-journal-observer-rotation-journal.yml"
VERIFIER = ROOT / "rust_057_observer_rotation_journal_verify.py"
SELFTEST = ROOT / "rust_057_observer_rotation_journal_selftest.py"
FIXTURE = ROOT / "rust_057_observer_rotation_journal_fixture.py"
BASE = ROOT / "rust_056_multistep_journal_monitor_journal_observer_rotation_verify.py"
DOC = ROOT / "RUST_057.md"
EXPECTED_RUST056_GIT_BLOB = "4de7e629a8bac1cff71e5d694ff962e3f6e9b714"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_054_journal_monitor_journal_gossip_verify",
    "rust_055_journal_monitor_journal_observer_set_rotation_verify",
    "rust_056_multistep_journal_monitor_journal_observer_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_057_observer_rotation_journal_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST056_GIT_BLOB
    assert "import rust_056_multistep_journal_monitor_journal_observer_rotation_verify as rotation2_verify" in verifier
    checks += 1
    print("[GREEN] exact reviewed RUST-056 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in ("cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib", "socket", "import axven", "from axven"):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached observer-journal verifier/selftest have no signing or network capability")

    for marker in (
        'JOURNAL_SCHEMA = "axven-native-journal-monitor-journal-observer-set-rotation-journal-v1"',
        'CHECKPOINT_DOMAIN = b"AXVEN_NATIVE_JOURNAL_MONITOR_JOURNAL_OBSERVER_SET_ROTATION_JOURNAL_CHECKPOINT_V1\\x00"',
        "THRESHOLD = 2", '"rotation_auth_sha256"', '"observed_checkpoint_sha256"',
        '"observed_checkpoint_statement_sha256"',
        'raise AssertionError("observed same-parent observer-rotation-journal checkpoint fork")',
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] append-only journal, exact bindings, 2-of-3 checkpoints, and fork rejection are fixed")

    for marker in (
        "permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"',
        "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust057-*.json",
        'test ! -e "$c/rust_057_observer_rotation_journal_fixture.py"',
    ):
        assert marker in workflow, marker
    for forbidden in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, and non-publishing")

    for marker in ('"ab" * 32', '"bb" * 32', '"cb" * 32', '"db" * 32', "Ed25519PrivateKey", "RUST-057 TEST-only observer journal public-key pin mismatch"):
        assert marker in fixture, marker
    assert "rust_057_observer_rotation_journal_fixture.py" in workflow
    assert "rust_057_observer_rotation_journal_selftest.py" in workflow
    checks += 1
    print("[GREEN] deterministic observer checkpoint private fixtures remain producer-side")

    for marker in (
        "O1/O2/O3 -> O2/O3/O4 -> O3/O4/O5",
        "exact RUST-053 final journal-monitor-journal checkpoint SHA-256",
        "cumulative revocation `[O1, O2]`",
        "same-parent final observer-rotation-journal checkpoint fork",
        "Production consensus remains Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] documentation preserves TEST-only journal and inherited binding boundary")

    assert checks == 6
    print("RUST-057 observer rotation journal static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
