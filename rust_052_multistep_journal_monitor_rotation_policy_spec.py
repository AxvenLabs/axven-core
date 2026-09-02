#!/usr/bin/env python3
"""RUST-052 static policy for TEST-ONLY multi-step journal-monitor set rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-multistep-journal-monitor-rotation.yml"
VERIFIER = ROOT / "rust_052_multistep_journal_monitor_rotation_verify.py"
FIXTURE = ROOT / "rust_052_multistep_journal_monitor_rotation_fixture.py"
SELFTEST = ROOT / "rust_052_multistep_journal_monitor_rotation_selftest.py"
BASE = ROOT / "rust_051_journal_monitor_set_rotation_verify.py"
DOC = ROOT / "RUST_052.md"
EXPECTED_RUST051_GIT_BLOB = "07e456a8ae49a08029d2193f499d91a09d3df283"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify",
    "rust_032_external_monotonic_floor_verify",
    "rust_050_journal_observer_journal_monitor_verify",
    "rust_051_journal_monitor_set_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys",
    "tempfile", "rust_030_stdlib_material_verify",
    "rust_032_external_monotonic_floor_verify",
    "rust_052_multistep_journal_monitor_rotation_verify",
}


def blob(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()


def roots(src: str) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            out.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module.split(".", 1)[0])
    return out


def main() -> None:
    v = VERIFIER.read_text(encoding="utf-8")
    f = FIXTURE.read_text(encoding="utf-8")
    s = SELFTEST.read_text(encoding="utf-8")
    w = WORKFLOW.read_text(encoding="utf-8")
    d = DOC.read_text(encoding="utf-8")
    checks = 0

    assert blob(BASE.read_bytes()) == EXPECTED_RUST051_GIT_BLOB
    assert "import rust_051_journal_monitor_set_rotation_verify as rotation1_verify" in v
    checks += 1
    print("[GREEN] exact reviewed RUST-051 verifier is composed")

    assert roots(v) <= ALLOWED_VERIFIER_IMPORTS
    assert roots(s) <= ALLOWED_SELFTEST_IMPORTS
    for token in (
        "cryptography", "Ed25519PrivateKey", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert token not in v and token not in s, token
    checks += 1
    print("[GREEN] detached RUST-052 verifier/selftest have no private signing or network capability")

    for token in (
        'FINAL_SET_SEQUENCE = 2',
        'JM5_ID = "rust-052-test-only-journal-monitor-5-v1"',
        'CUMULATIVE_REVOKED_MONITOR_IDS',
        '"predecessor_rotation_sha256"',
        '"predecessor_rotation_auth_sha256"',
        '"predecessor_successor_bundle_sha256"',
        '"journal_observer_checkpoint_sha256"',
        '"monitor_journal_checkpoint_sha256"',
        '"monitor_journal_checkpoint_statement_sha256"',
        'raise AssertionError("observed final journal-monitor same-parent journal-observer-journal checkpoint fork")',
    ):
        assert token in v, token
    checks += 1
    print("[GREEN] second journal-monitor rotation, cumulative revocation, predecessor chain and split-view rejection are pinned")

    for token in (
        "permissions:\n  contents: read",
        "persist-credentials: false",
        'python-version: "3.13.15"',
        "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust052-",
    ):
        assert token in w, token
    for token in (
        "id-token: write", "actions/upload-artifact", "attest", "release", "deploy"
    ):
        assert token not in w.lower(), token
    checks += 1
    print("[GREEN] workflow stays detached, read-only and non-publishing")

    for token in (
        '"6a" * 32', '"7a" * 32', '"8a" * 32', '"9a" * 32',
        "Ed25519PrivateKey",
        "RUST-052 TEST-only journal-monitor public-key pin mismatch",
    ):
        assert token in f, token
    assert "old-rust051-successor-bundle-replay" in s
    assert "signed-final-same-parent-split-view" in s
    checks += 1
    print("[GREEN] predecessor/final availability, replay rejection and producer-only private keys are pinned")

    for token in (
        "JM1/JM2/JM3 -> JM2/JM3/JM4 -> JM3/JM4/JM5",
        "cumulative revocation", "2-of-3", "TEST-only",
        "Production consensus remains Python-authoritative",
    ):
        assert token in d, token
    checks += 1
    print("[GREEN] documentation preserves TEST-only multi-step journal-monitor boundary")

    assert checks == 6
    print("RUST-052 multi-step journal-monitor rotation static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
