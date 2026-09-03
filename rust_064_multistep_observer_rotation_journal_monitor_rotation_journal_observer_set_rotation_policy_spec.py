#!/usr/bin/env python3
"""RUST-064 static policy for TEST-ONLY multi-step monitor-rotation-journal observer rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-multistep-observer-rotation-journal-monitor-rotation-journal-observer-set-rotation.yml"
VERIFIER = ROOT / "rust_064_multistep_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify.py"
SELFTEST = ROOT / "rust_064_multistep_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_selftest.py"
FIXTURE = ROOT / "rust_064_multistep_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_fixture.py"
BASE = ROOT / "rust_063_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify.py"
DOC = ROOT / "RUST_064.md"
EXPECTED_RUST063_GIT_BLOB = "ec88d1c060e7437bec67c14d08d61b20d909b57f"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify",
    "rust_032_external_monotonic_floor_verify",
    "rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_verify",
    "rust_063_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys",
    "tempfile", "rust_030_stdlib_material_verify",
    "rust_032_external_monotonic_floor_verify",
    "rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_verify",
    "rust_064_multistep_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify",
}


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def blob(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()


def roots(source: str) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            out.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module.split(".", 1)[0])
    return out


def main() -> None:
    v = text(VERIFIER)
    s = text(SELFTEST)
    f = text(FIXTURE)
    w = text(WORKFLOW)
    d = text(DOC)
    checks = 0

    assert blob(BASE.read_bytes()) == EXPECTED_RUST063_GIT_BLOB
    assert (
        "import rust_063_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify as rotation1_verify"
        in v
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-063 verifier is composed")

    assert roots(v) <= ALLOWED_VERIFIER_IMPORTS
    assert roots(s) <= ALLOWED_SELFTEST_IMPORTS
    for token in (
        "cryptography", "Ed25519PrivateKey", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert token not in v and token not in s, token
    checks += 1
    print("[GREEN] detached RUST-064 verifier/selftest have no signing or network capability")

    for token in (
        'ROTATION_SCHEMA = "axven-native-observer-rotation-journal-monitor-set-rotation-journal-observer-set-rotation-v2"',
        'FINAL_BUNDLE_SCHEMA = "axven-native-observer-rotation-journal-monitor-set-rotation-journal-checkpoint-observation-bundle-v3"',
        "FINAL_SET_SEQUENCE = 2",
        "THRESHOLD = 2",
        'O5_ID = "rust-064-test-only-monitor-rotation-journal-observer-5-v1"',
        'O5_PUBLIC_KEY = bytes.fromhex("e34d3a01b6112e1429ead61668405f4ef4be4f8853abee5079d28ac6c13ffdd0")',
        'raise AssertionError("predecessor monitor-rotation-journal observer rotation authorization digest mismatch")',
        'raise AssertionError("predecessor monitor-rotation-journal successor observer bundle digest mismatch")',
        "observed final same-parent observer-rotation-journal monitor-rotation-journal checkpoint fork",
    ):
        assert token in v, token
    checks += 1
    print("[GREEN] multi-step predecessor, cumulative revocation and split-view contracts are pinned")

    for token in (
        "permissions:\n  contents: read",
        "persist-credentials: false",
        'python-version: "3.13.15"',
        "env -i",
        "/usr/bin/python3 -S",
        "chmod 0444 /tmp/axven-rust064-*.json",
        'test ! -e "$c/rust_064_multistep_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_fixture.py"',
    ):
        assert token in w, token
    for token in (
        "id-token: write", "actions/upload-artifact", "attest", "release", "deploy",
    ):
        assert token not in w.lower(), token
    checks += 1
    print("[GREEN] workflow stays detached, read-only and non-publishing")

    for token in (
        '"39" * 32', '"49" * 32', '"59" * 32', '"69" * 32',
        "Ed25519PrivateKey",
        "RUST-064 TEST-only monitor-rotation-journal observer public-key pin mismatch",
    ):
        assert token in f, token
    assert "3/3 valid two-observer subsets accepted" in s
    assert "36/36 expected cases passed" in s
    checks += 1
    print("[GREEN] availability, fail-closed matrix and producer-only private keys are pinned")

    for token in (
        "O1/O2/O3 -> O2/O3/O4 -> O3/O4/O5",
        "cumulative revocation `[O1, O2]`",
        "RUST-063 v2 successor bundle cannot replay",
        "same monitor-set sequence and same previous-checkpoint parent",
        "Production consensus remains Python-authoritative",
    ):
        assert token in d, token
    checks += 1
    print("[GREEN] documentation preserves multi-step TEST-only observer boundary")

    assert checks == 6
    print(
        "RUST-064 multi-step monitor-rotation-journal observer set rotation "
        "static policy: 6/6 checks passed"
    )


if __name__ == "__main__":
    main()
