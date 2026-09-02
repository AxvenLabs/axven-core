#!/usr/bin/env python3
"""RUST-036 static policy for TEST-ONLY multi-step witness rotation."""
from __future__ import annotations
import ast, hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
WORKFLOW=ROOT/".github/workflows/native-multistep-witness-rotation.yml"
VERIFIER=ROOT/"rust_036_multistep_witness_rotation_verify.py"
BASE=ROOT/"rust_035_witness_set_rotation_verify.py"
DOC=ROOT/"RUST_036.md"
FIXTURE=ROOT/"rust_036_multistep_witness_rotation_fixture.py"
EXPECTED_RUST035_GIT_BLOB="bc45f322a77b8604467f07a02448d6459efb3c09"
ALLOWED_IMPORTS={"__future__","base64","copy","hashlib","json","pathlib","sys","tempfile","rust_030_stdlib_material_verify","rust_032_external_monotonic_floor_verify","rust_035_witness_set_rotation_verify"}
def text(p): return p.read_text(encoding="utf-8")
def roots(src):
    out=set()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n,ast.Import): out.update(a.name.split('.',1)[0] for a in n.names)
        elif isinstance(n,ast.ImportFrom) and n.module: out.add(n.module.split('.',1)[0])
    return out
def blob(raw): return hashlib.sha1(f"blob {len(raw)}\0".encode()+raw).hexdigest()
def main():
    v=text(VERIFIER); w=text(WORKFLOW); d=text(DOC); f=text(FIXTURE); checks=0
    assert blob(BASE.read_bytes())==EXPECTED_RUST035_GIT_BLOB
    assert "import rust_035_witness_set_rotation_verify as rotation1_verify" in v
    checks+=1; print("[GREEN] exact reviewed RUST-035 verifier is composed")
    assert roots(v)<=ALLOWED_IMPORTS
    for x in ("cryptography","Ed25519PrivateKey",".sign(","subprocess","requests","urllib","socket","import axven","from axven"): assert x not in v
    checks+=1; print("[GREEN] detached multi-step verifier has no signing/network capability")
    for x in ('SECOND_ROTATION_SCHEMA = "axven-native-external-floor-witness-set-rotation-v2"','FINAL_QUORUM_SCHEMA = "axven-native-external-floor-witness-quorum-v3"','FINAL_SET_SEQUENCE = 2','E_KEY_ID = "rust-036-test-only-floor-witness-e-v1"','E_PUBLIC_KEY = bytes.fromhex("d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48")','CUMULATIVE_REVOKED_KEY_IDS = sorted([REVOKED_A_KEY_ID, REVOKED_B_KEY_ID])','predecessor_rotation_sha256'):
        assert x in v,x
    checks+=1; print("[GREEN] sequence-2 set, E key, cumulative revocation and predecessor record binding are pinned")
    for x in ("permissions:\n  contents: read","persist-credentials: false","python-version: \"3.13.15\"","env -i","/usr/bin/python3 -S",'chmod 0444 /tmp/axven-rust036-external-floor.json'):
        assert x in w,x
    for x in ("id-token: write","actions/upload-artifact","attest","release","deploy"): assert x not in w.lower()
    checks+=1; print("[GREEN] workflow stays detached, read-only and non-publishing")
    for x in (
        "0bcea6c25bf2e920391237f68a9ff4d36f3e8800521f93016ed2b4a10c81a09f",
        "'rust-034-test-only-floor-witness-b-v1':'11'*32",
        "'rust-034-test-only-floor-witness-c-v1':'22'*32",
        "'rust-035-test-only-floor-witness-d-v1':'33'*32",
        "'rust-036-test-only-floor-witness-e-v1':'44'*32",
    ):
        assert x in f,x
    for x in ("cryptography.hazmat.primitives.asymmetric.ed25519", "Ed25519PrivateKey", "RUST-036 TEST-only public-key pin mismatch"):
        assert x in f,x
    assert "rust_036_multistep_witness_rotation_fixture.py" in w
    checks+=1; print("[GREEN] all TEST fixture seeds remain producer-side")
    for x in ("A/B/C","B/C/D","C/D/E","cumulative revoked set `[A, B]`","Production consensus remains Python-authoritative"):
        assert x in d,x
    checks+=1; print("[GREEN] documentation preserves multi-step TEST-only boundary")
    assert checks==6
    print("RUST-036 multi-step witness rotation static policy: 6/6 checks passed")
if __name__=="__main__": main()
