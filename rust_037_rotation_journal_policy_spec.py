#!/usr/bin/env python3
"""RUST-037 static policy for TEST-ONLY append-only rotation journal continuity."""
from __future__ import annotations
import ast, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-rotation-journal.yml"
VERIFIER = ROOT / "rust_037_rotation_journal_verify.py"
FIXTURE = ROOT / "rust_037_rotation_journal_fixture.py"
SELFTEST = ROOT / "rust_037_rotation_journal_selftest.py"
BASE = ROOT / "rust_036_multistep_witness_rotation_verify.py"
DOC = ROOT / "RUST_037.md"
EXPECTED_RUST036_GIT_BLOB = "4f106f939533fc206e0744a3a818b0d582ad4693"
ALLOWED_IMPORTS = {
    "__future__", "base64", "copy", "hashlib", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_035_witness_set_rotation_verify", "rust_036_multistep_witness_rotation_verify",
}

def text(path): return path.read_text(encoding="utf-8")
def blob(raw): return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
def roots(src):
    out=set()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Import): out.update(a.name.split('.',1)[0] for a in n.names)
        elif isinstance(n, ast.ImportFrom) and n.module: out.add(n.module.split('.',1)[0])
    return out

def main():
    v=text(VERIFIER); f=text(FIXTURE); t=text(SELFTEST); w=text(WORKFLOW); d=text(DOC); checks=0
    assert blob(BASE.read_bytes()) == EXPECTED_RUST036_GIT_BLOB
    assert "import rust_036_multistep_witness_rotation_verify as rotation2_verify" in v
    checks += 1; print("[GREEN] exact reviewed RUST-036 verifier is composed")

    assert roots(v) <= ALLOWED_IMPORTS
    assert roots(t) <= ALLOWED_IMPORTS | {"rust_037_rotation_journal_verify"}
    for x in ("cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib", "socket", "import axven", "from axven"):
        assert x not in v and x not in t, x
    checks += 1; print("[GREEN] detached journal verifier has no signing/network capability")

    for x in (
        'axven-native-witness-rotation-journal-v1',
        'axven-native-witness-rotation-journal-checkpoint-v1',
        'AXVEN_NATIVE_WITNESS_ROTATION_JOURNAL_CHECKPOINT_V1\\x00',
        '"previous_checkpoint_sha256"', '"predecessor_entry_sha256"',
        'raise AssertionError("observed same-parent checkpoint fork")',
    ):
        assert x in v, x
    checks += 1; print("[GREEN] append-only entry chain, parent checkpoint binding, and observed-fork rejection are pinned")

    for x in ("permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"', "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust037-prefix-journal.json"):
        assert x in w, x
    for x in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert x not in w.lower(), x
    checks += 1; print("[GREEN] workflow stays detached, read-only, and non-publishing")

    for x in ('"11" * 32', '"22" * 32', '"33" * 32', '"44" * 32', "Ed25519PrivateKey", "RUST-037 TEST-only public-key pin mismatch"):
        assert x in f, x
    assert "rust_037_rotation_journal_fixture.py" in w and "rust_037_rotation_journal_selftest.py" in w
    checks += 1; print("[GREEN] checkpoint signing fixtures remain producer-side")

    for x in ("A/B/C -> B/C/D -> C/D/E", "same-sequence checkpoints", "does **not** provide global gossip", "Production consensus remains Python-authoritative"):
        assert x in d, x
    checks += 1; print("[GREEN] documentation preserves TEST-only transparency boundary")

    assert checks == 6
    print("RUST-037 rotation journal static policy: 6/6 checks passed")

if __name__ == "__main__": main()
