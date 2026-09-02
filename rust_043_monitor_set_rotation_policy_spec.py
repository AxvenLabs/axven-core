#!/usr/bin/env python3
"""RUST-043 static policy for TEST-only monitor-set rotation/revocation continuity."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-monitor-set-rotation.yml"
VERIFIER = ROOT / "rust_043_monitor_set_rotation_verify.py"
FIXTURE = ROOT / "rust_043_monitor_set_rotation_fixture.py"
SELFTEST = ROOT / "rust_043_monitor_set_rotation_selftest.py"
BASE = ROOT / "rust_042_observer_journal_monitor_verify.py"
DOC = ROOT / "RUST_043.md"
EXPECTED_RUST042_GIT_BLOB = "ce1aeb93bbb276faa3aac196c82615d93796374e"
ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_041_observer_rotation_journal_verify", "rust_042_observer_journal_monitor_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_043_monitor_set_rotation_verify",
}


def text(path: Path) -> str: return path.read_text(encoding="utf-8")
def blob(raw: bytes) -> str: return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()

def roots(src: str) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import): out.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module: out.add(node.module.split(".", 1)[0])
    return out


def main() -> None:
    v=text(VERIFIER); f=text(FIXTURE); s=text(SELFTEST); w=text(WORKFLOW); d=text(DOC); checks=0
    assert blob(BASE.read_bytes()) == EXPECTED_RUST042_GIT_BLOB
    assert "import rust_042_observer_journal_monitor_verify as monitor_verify" in v
    checks += 1; print("[GREEN] exact reviewed RUST-042 verifier is composed")

    assert roots(v) <= ALLOWED_VERIFIER_IMPORTS
    assert roots(s) <= ALLOWED_SELFTEST_IMPORTS
    for token in ("cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib", "socket", "import axven", "from axven"):
        assert token not in v and token not in s, token
    checks += 1; print("[GREEN] detached RUST-043 verifier/selftest have no private signing or network capability")

    for token in (
        'NEW_SET_SEQUENCE = 1', 'rust-043-test-only-monitor-4-v1', 'REVOKED_MONITOR_ID = monitor_verify.MONITOR_1_ID',
        '"predecessor_monitor_bundle_sha256"', '"checkpoint_sha256"',
        'raise AssertionError("observed successor monitor same-parent observer-journal fork")',
    ):
        assert token in v, token
    assert "old-rust042-monitor-bundle-replay" in s
    checks += 1; print("[GREEN] M1 revocation, M4, predecessor binding, epoch-1 and replay rejection are pinned")

    for token in ("permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"', "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust043-monitor-set-rotation.json"):
        assert token in w, token
    for token in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert token not in w.lower(), token
    checks += 1; print("[GREEN] workflow stays detached, read-only and non-publishing")

    for token in ('"aa" * 32', '"bb" * 32', '"cc" * 32', '"dd" * 32', "Ed25519PrivateKey", "RUST-043 TEST-only monitor public-key pin mismatch"):
        assert token in f, token
    assert "rust_043_monitor_set_rotation_fixture.py" in w and "rust_043_monitor_set_rotation_selftest.py" in w
    checks += 1; print("[GREEN] predecessor/successor monitor private signing remains producer-side")

    for token in ("M1/M2/M3", "M2/M3/M4", "explicitly revokes `M1`", "does **not** create independent monitor administration/custody", "Production consensus remains Python-authoritative"):
        assert token in d, token
    checks += 1; print("[GREEN] documentation preserves TEST-only monitor key-management boundary")

    assert checks == 6
    print("RUST-043 monitor-set rotation static policy: 6/6 checks passed")

if __name__ == "__main__": main()
