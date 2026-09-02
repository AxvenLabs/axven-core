#!/usr/bin/env python3
"""RUST-045 static policy for TEST-ONLY monitor rotation journal/checkpoint continuity."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal.yml"
VERIFIER = ROOT / "rust_045_monitor_rotation_journal_verify.py"
FIXTURE = ROOT / "rust_045_monitor_rotation_journal_fixture.py"
SELFTEST = ROOT / "rust_045_monitor_rotation_journal_selftest.py"
BASE = ROOT / "rust_044_multistep_monitor_rotation_verify.py"
DOC = ROOT / "RUST_045.md"
EXPECTED_RUST044_GIT_BLOB = "862c03bae433892d0c70bf275bbefadff775623a"
ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_042_observer_journal_monitor_verify", "rust_043_monitor_set_rotation_verify",
    "rust_044_multistep_monitor_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_043_monitor_set_rotation_verify", "rust_044_multistep_monitor_rotation_verify",
    "rust_045_monitor_rotation_journal_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST044_GIT_BLOB
    assert "import rust_044_multistep_monitor_rotation_verify as rotation2_verify" in v
    checks += 1; print("[GREEN] exact reviewed RUST-044 verifier is composed")

    assert roots(v) <= ALLOWED_VERIFIER_IMPORTS
    assert roots(s) <= ALLOWED_SELFTEST_IMPORTS
    for token in ("cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib", "socket", "import axven", "from axven"):
        assert token not in v and token not in s, token
    checks += 1; print("[GREEN] detached RUST-045 verifier/selftest have no private signing or network capability")

    for token in (
        'JOURNAL_SCHEMA = "axven-native-observer-journal-monitor-set-rotation-journal-v1"',
        '"rotation_auth_sha256"', '"monitor_bundle_sha256"', '"predecessor_entry_sha256"',
        '"previous_checkpoint_sha256"',
        'raise AssertionError("final monitor journal rewrites checkpointed prefix")',
        'raise AssertionError("observed same-parent monitor-rotation-journal checkpoint fork")',
    ):
        assert token in v, token
    checks += 1; print("[GREEN] append-only monitor journal, checkpoint chaining and split-view rejection are pinned")

    for token in (
        "permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"',
        "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust045-",
    ):
        assert token in w, token
    for token in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert token not in w.lower(), token
    checks += 1; print("[GREEN] workflow stays detached, read-only and non-publishing")

    for token in (
        '"bb" * 32', '"cc" * 32', '"dd" * 32', '"ee" * 32', "Ed25519PrivateKey",
        "RUST-045 TEST-only monitor journal public-key pin mismatch",
    ):
        assert token in f, token
    assert "3/3 valid two-monitor subsets accepted" in s
    assert "observed-valid-same-parent-monitor-rotation-journal-fork" in s
    checks += 1; print("[GREEN] monitor checkpoint availability, fork rejection and producer-only private keys are pinned")

    for token in (
        "M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5", "append-only journal", "2-of-3", "TEST-only",
        "does **not** create independent monitor administration", "Production consensus remains Python-authoritative",
    ):
        assert token in d, token
    checks += 1; print("[GREEN] documentation preserves TEST-only monitor-journal boundary")

    assert checks == 6
    print("RUST-045 monitor rotation journal static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
