#!/usr/bin/env python3
"""RUST-041 static policy for TEST-ONLY observer rotation journal/checkpoint continuity."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-observer-rotation-journal.yml"
VERIFIER = ROOT / "rust_041_observer_rotation_journal_verify.py"
FIXTURE = ROOT / "rust_041_observer_rotation_journal_fixture.py"
SELFTEST = ROOT / "rust_041_observer_rotation_journal_selftest.py"
BASE = ROOT / "rust_040_multistep_observer_rotation_verify.py"
DOC = ROOT / "RUST_041.md"
EXPECTED_RUST040_GIT_BLOB = "9afc3513926fe9d47d8080aa5443b67662f13180"
ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_038_checkpoint_gossip_verify", "rust_039_observer_set_rotation_verify",
    "rust_040_multistep_observer_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_038_checkpoint_gossip_verify", "rust_039_observer_set_rotation_verify",
    "rust_040_multistep_observer_rotation_verify", "rust_041_observer_rotation_journal_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST040_GIT_BLOB
    assert "import rust_040_multistep_observer_rotation_verify as rotation2_verify" in v
    checks += 1; print("[GREEN] exact reviewed RUST-040 verifier is composed")

    assert roots(v) <= ALLOWED_VERIFIER_IMPORTS
    assert roots(s) <= ALLOWED_SELFTEST_IMPORTS
    for token in ("cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib", "socket", "import axven", "from axven"):
        assert token not in v and token not in s, token
    checks += 1; print("[GREEN] detached RUST-041 verifier/selftest have no private signing or network capability")

    for token in (
        'JOURNAL_SCHEMA = "axven-native-observer-set-rotation-journal-v1"',
        '"rotation_auth_sha256"', '"observation_bundle_sha256"',
        '"predecessor_entry_sha256"', '"previous_checkpoint_sha256"',
        'raise AssertionError("final observer journal rewrites checkpointed prefix")',
        'raise AssertionError("observed same-parent observer-journal checkpoint fork")',
    ):
        assert token in v, token
    checks += 1; print("[GREEN] append-only observer journal, checkpoint chaining and split-view rejection are pinned")

    for token in (
        "permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"',
        "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust041-prefix-observer-journal.json",
    ):
        assert token in w, token
    for token in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert token not in w.lower(), token
    checks += 1; print("[GREEN] workflow stays detached, read-only and non-publishing")

    for token in ('"66" * 32', '"77" * 32', '"88" * 32', '"99" * 32', "Ed25519PrivateKey", "RUST-041 TEST-only observer journal public-key pin mismatch"):
        assert token in f, token
    assert "rust_041_observer_rotation_journal_fixture.py" in w
    assert "rust_041_observer_rotation_journal_selftest.py" in w
    checks += 1; print("[GREEN] observer journal private signing fixtures remain producer-side")

    for token in (
        "O1/O2/O3 -> O2/O3/O4 -> O3/O4/O5", "[O1, O2]", "append-only journal",
        "does **not** create independent observer administration", "Production consensus remains Python-authoritative",
    ):
        assert token in d, token
    checks += 1; print("[GREEN] documentation preserves TEST-only observer-journal boundary")

    assert checks == 6
    print("RUST-041 observer rotation journal static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
