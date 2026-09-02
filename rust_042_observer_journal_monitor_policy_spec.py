#!/usr/bin/env python3
"""RUST-042 static policy for TEST-only observer-journal checkpoint monitoring."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-observer-journal-monitor.yml"
VERIFIER = ROOT / "rust_042_observer_journal_monitor_verify.py"
FIXTURE = ROOT / "rust_042_observer_journal_monitor_fixture.py"
SELFTEST = ROOT / "rust_042_observer_journal_monitor_selftest.py"
BASE = ROOT / "rust_041_observer_rotation_journal_verify.py"
DOC = ROOT / "RUST_042.md"
EXPECTED_RUST041_GIT_BLOB = "3a987d1b40c81b43ba92dd82dc1a664cdd4d9c3d"
ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_040_multistep_observer_rotation_verify", "rust_041_observer_rotation_journal_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_042_observer_journal_monitor_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST041_GIT_BLOB
    assert "import rust_041_observer_rotation_journal_verify as journal_verify" in v
    checks += 1; print("[GREEN] exact reviewed RUST-041 verifier is composed")

    assert roots(v) <= ALLOWED_VERIFIER_IMPORTS
    assert roots(s) <= ALLOWED_SELFTEST_IMPORTS
    for token in ("cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib", "socket", "import axven", "from axven"):
        assert token not in v and token not in s, token
    checks += 1; print("[GREEN] detached RUST-042 verifier/selftest have no private signing or network capability")

    for token in (
        'THRESHOLD = 2', 'rust-042-test-only-monitor-1-v1', 'rust-042-test-only-monitor-2-v1',
        'rust-042-test-only-monitor-3-v1', '"checkpoint_sha256"', '"previous_checkpoint_sha256"',
        'raise AssertionError("observed monitor same-parent observer-journal fork")',
    ):
        assert token in v, token
    checks += 1; print("[GREEN] 2-of-3 monitor quorum, exact checkpoint binding and strict split-view rejection are pinned")

    for token in ("permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"', "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust042-monitor-bundle.json"):
        assert token in w, token
    for token in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert token not in w.lower(), token
    checks += 1; print("[GREEN] workflow stays detached, read-only and non-publishing")

    for token in ('"aa" * 32', '"bb" * 32', '"cc" * 32', "Ed25519PrivateKey", "RUST-042 TEST-only monitor public-key pin mismatch"):
        assert token in f, token
    assert "rust_042_observer_journal_monitor_fixture.py" in w
    assert "rust_042_observer_journal_monitor_selftest.py" in w
    checks += 1; print("[GREEN] TEST monitor private signing remains producer-side")

    for token in ("M1/M2/M3", "2-of-3", "same observer-set sequence", "does **not** create independent monitor administration", "Production consensus remains Python-authoritative"):
        assert token in d, token
    checks += 1; print("[GREEN] documentation preserves TEST-only monitoring boundary")

    assert checks == 6
    print("RUST-042 observer-journal monitor static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
