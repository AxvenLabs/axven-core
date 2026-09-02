#!/usr/bin/env python3
"""RUST-048 static policy for TEST-ONLY multi-step journal-observer rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-multistep-journal-observer-rotation.yml"
VERIFIER = ROOT / "rust_048_multistep_journal_observer_rotation_verify.py"
SELFTEST = ROOT / "rust_048_multistep_journal_observer_rotation_selftest.py"
FIXTURE = ROOT / "rust_048_multistep_journal_observer_rotation_fixture.py"
BASE = ROOT / "rust_047_journal_observer_set_rotation_verify.py"
DOC = ROOT / "RUST_048.md"
EXPECTED_RUST047_GIT_BLOB = "c1f9d01c64da4957f32d49e61bf9ae1606000585"
ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys", "rust_030_stdlib_material_verify",
    "rust_032_external_monotonic_floor_verify", "rust_046_monitor_journal_gossip_verify",
    "rust_047_journal_observer_set_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_046_monitor_journal_gossip_verify", "rust_048_multistep_journal_observer_rotation_verify",
}


def text(path: Path) -> str: return path.read_text(encoding="utf-8")
def blob(raw: bytes) -> str: return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()

def imported_roots(source: str) -> set[str]:
    roots = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import): roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module: roots.add(node.module.split(".", 1)[0])
    return roots


def main() -> None:
    verifier, selftest, fixture, workflow, doc = map(text, (VERIFIER, SELFTEST, FIXTURE, WORKFLOW, DOC))
    checks = 0
    assert blob(BASE.read_bytes()) == EXPECTED_RUST047_GIT_BLOB
    assert "import rust_047_journal_observer_set_rotation_verify as rotation1_verify" in verifier
    checks += 1; print("[GREEN] exact reviewed RUST-047 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in ("cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib", "socket", "import axven", "from axven"):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1; print("[GREEN] detached verifier/selftest have no signing or network capability")

    for marker in (
        'ROTATION_SCHEMA = "axven-native-monitor-journal-observer-set-rotation-v2"',
        'FINAL_BUNDLE_SCHEMA = "axven-native-monitor-rotation-journal-checkpoint-observation-bundle-v3"',
        "FINAL_SET_SEQUENCE = 2", "THRESHOLD = 2",
        'J5_ID = "rust-048-test-only-journal-observer-5-v1"',
        'J5_PUBLIC_KEY = bytes.fromhex("00e3c56b91ab0a017174b96645eaf928366cdbae1e87fd21bf86661d86f3e7ef")',
        'raise AssertionError("predecessor journal-observer rotation digest mismatch")',
        'raise AssertionError("predecessor journal-observer bundle digest mismatch")',
        'raise AssertionError("observed final same-parent monitor-journal checkpoint fork")',
    ): assert marker in verifier, marker
    checks += 1; print("[GREEN] multi-step predecessor, cumulative revocation, and split-view contracts are fixed")

    for marker in ("permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"', "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust048-*.json", 'test ! -e "$c/rust_048_multistep_journal_observer_rotation_fixture.py"'):
        assert marker in workflow, marker
    for forbidden in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"): assert forbidden not in workflow.lower(), forbidden
    checks += 1; print("[GREEN] workflow stays detached, read-only, and non-publishing")

    for marker in ('"1f" * 32', '"2f" * 32', '"3f" * 32', '"4f" * 32', "Ed25519PrivateKey", "RUST-048 TEST-only journal-observer public-key pin mismatch"):
        assert marker in fixture, marker
    checks += 1; print("[GREEN] deterministic TEST private fixtures remain producer-side")

    for marker in ("J1/J2/J3 -> J2/J3/J4 -> J3/J4/J5", "cumulative revocation list `[J1, J2]`", "RUST-047 v2 successor bundle cannot replay", "same monitor-set sequence and same previous-checkpoint parent", "Production consensus remains Python-authoritative"):
        assert marker in doc, marker
    checks += 1; print("[GREEN] documentation preserves multi-step TEST-only boundary")

    assert checks == 6
    print("RUST-048 multi-step journal-observer rotation static policy: 6/6 checks passed")


if __name__ == "__main__": main()
