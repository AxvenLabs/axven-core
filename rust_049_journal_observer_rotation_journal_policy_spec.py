#!/usr/bin/env python3
"""RUST-049 static policy for TEST-ONLY journal-observer rotation journal/checkpoint continuity."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-journal-observer-rotation-journal.yml"
VERIFIER = ROOT / "rust_049_journal_observer_rotation_journal_verify.py"
FIXTURE = ROOT / "rust_049_journal_observer_rotation_journal_fixture.py"
SELFTEST = ROOT / "rust_049_journal_observer_rotation_journal_selftest.py"
BASE = ROOT / "rust_048_multistep_journal_observer_rotation_verify.py"
DOC = ROOT / "RUST_049.md"
EXPECTED_RUST048_GIT_BLOB = "6dacce6b7a225cb8abb6284730b1a7b2190bac7c"
ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_046_monitor_journal_gossip_verify", "rust_047_journal_observer_set_rotation_verify",
    "rust_048_multistep_journal_observer_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_047_journal_observer_set_rotation_verify",
    "rust_048_multistep_journal_observer_rotation_verify",
    "rust_049_journal_observer_rotation_journal_verify",
}


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def blob(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()


def roots(src: str) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            out.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module.split(".", 1)[0])
    return out


def main() -> None:
    v = text(VERIFIER); f = text(FIXTURE); s = text(SELFTEST); w = text(WORKFLOW); d = text(DOC); checks = 0

    assert blob(BASE.read_bytes()) == EXPECTED_RUST048_GIT_BLOB
    assert "import rust_048_multistep_journal_observer_rotation_verify as rotation2_verify" in v
    checks += 1; print("[GREEN] exact reviewed RUST-048 verifier is composed")

    assert roots(v) <= ALLOWED_VERIFIER_IMPORTS
    assert roots(s) <= ALLOWED_SELFTEST_IMPORTS
    for token in ("cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib", "socket", "import axven", "from axven"):
        assert token not in v and token not in s, token
    checks += 1; print("[GREEN] detached RUST-049 verifier/selftest have no private signing or network capability")

    for token in (
        'JOURNAL_SCHEMA = "axven-native-monitor-journal-observer-set-rotation-journal-v1"',
        '"rotation_auth_sha256"', '"observer_bundle_sha256"', '"predecessor_entry_sha256"',
        '"previous_checkpoint_sha256"',
        'raise AssertionError("final journal-observer journal rewrites checkpointed prefix")',
        'raise AssertionError("observed same-parent journal-observer-rotation-journal checkpoint fork")',
    ):
        assert token in v, token
    checks += 1; print("[GREEN] append-only journal-observer history, checkpoint chaining and split-view rejection are pinned")

    for token in (
        "permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"',
        "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust049-",
    ):
        assert token in w, token
    for token in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert token not in w.lower(), token
    checks += 1; print("[GREEN] workflow stays detached, read-only and non-publishing")

    for token in (
        '"1f" * 32', '"2f" * 32', '"3f" * 32', '"4f" * 32', "Ed25519PrivateKey",
        "RUST-049 TEST-only journal-observer journal public-key pin mismatch",
    ):
        assert token in f, token
    assert "3/3 valid two-observer subsets accepted" in s
    assert "observed-valid-same-parent-journal-observer-rotation-journal-fork" in s
    checks += 1; print("[GREEN] journal-observer checkpoint availability, fork rejection and producer-only private keys are pinned")

    for token in (
        "J1/J2/J3 -> J2/J3/J4 -> J3/J4/J5", "append-only journal", "2-of-3", "TEST-only",
        "does **not** create independent journal-observer administration", "Production consensus remains Python-authoritative",
    ):
        assert token in d, token
    checks += 1; print("[GREEN] documentation preserves TEST-only journal-observer journal boundary")

    assert checks == 6
    print("RUST-049 journal-observer rotation journal static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
