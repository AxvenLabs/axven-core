#!/usr/bin/env python3
"""RUST-050 static policy for TEST-ONLY journal-observer-journal checkpoint monitoring."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-journal-observer-journal-monitor.yml"
VERIFIER = ROOT / "rust_050_journal_observer_journal_monitor_verify.py"
FIXTURE = ROOT / "rust_050_journal_observer_journal_monitor_fixture.py"
SELFTEST = ROOT / "rust_050_journal_observer_journal_monitor_selftest.py"
BASE = ROOT / "rust_049_journal_observer_rotation_journal_verify.py"
DOC = ROOT / "RUST_050.md"
EXPECTED_RUST049_GIT_BLOB = "e11610c67c6ad2a7726eb7d7101ab29b60af56c5"
ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_048_multistep_journal_observer_rotation_verify",
    "rust_049_journal_observer_rotation_journal_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_050_journal_observer_journal_monitor_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST049_GIT_BLOB
    assert "import rust_049_journal_observer_rotation_journal_verify as journal_verify" in v
    checks += 1; print("[GREEN] exact reviewed RUST-049 verifier is composed")

    assert roots(v) <= ALLOWED_VERIFIER_IMPORTS
    assert roots(s) <= ALLOWED_SELFTEST_IMPORTS
    for token in ("cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib", "socket", "import axven", "from axven"):
        assert token not in v and token not in s, token
    checks += 1; print("[GREEN] detached RUST-050 verifier/selftest have no private signing or network capability")

    for token in (
        'THRESHOLD = 2',
        'rust-050-test-only-journal-monitor-1-v1',
        'rust-050-test-only-journal-monitor-2-v1',
        'rust-050-test-only-journal-monitor-3-v1',
        '"journal_observer_checkpoint_sha256"',
        '"previous_checkpoint_sha256"',
        'raise AssertionError("observed journal-monitor same-parent journal-observer-journal fork")',
    ):
        assert token in v, token
    checks += 1; print("[GREEN] 2-of-3 journal-monitor quorum, exact checkpoint binding and strict split-view rejection are pinned")

    for token in (
        "permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"',
        "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust050-monitor-bundle.json",
    ):
        assert token in w, token
    for token in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert token not in w.lower(), token
    checks += 1; print("[GREEN] workflow stays detached, read-only and non-publishing")

    for token in (
        '"5a" * 32', '"6a" * 32', '"7a" * 32', "Ed25519PrivateKey",
        "RUST-050 TEST-only journal-monitor public-key pin mismatch",
    ):
        assert token in f, token
    assert "3/3 valid two-monitor subsets accepted" in s
    assert "observed-valid-same-parent-journal-monitor-split-view" in s
    checks += 1; print("[GREEN] journal-monitor availability, fork rejection and producer-only private keys are pinned")

    for token in (
        "JM1/JM2/JM3", "2-of-3", "same observer-set sequence",
        "does **not** create independent journal-monitor administration",
        "Production consensus remains Python-authoritative",
    ):
        assert token in d, token
    checks += 1; print("[GREEN] documentation preserves TEST-only journal-monitor boundary")

    assert checks == 6
    print("RUST-050 journal-observer-journal monitor static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
