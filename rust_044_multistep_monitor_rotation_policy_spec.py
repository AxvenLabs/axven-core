#!/usr/bin/env python3
"""RUST-044 static policy for TEST-only multi-step monitor-set rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-multistep-monitor-rotation.yml"
VERIFIER = ROOT / "rust_044_multistep_monitor_rotation_verify.py"
FIXTURE = ROOT / "rust_044_multistep_monitor_rotation_fixture.py"
SELFTEST = ROOT / "rust_044_multistep_monitor_rotation_selftest.py"
BASE = ROOT / "rust_043_monitor_set_rotation_verify.py"
DOC = ROOT / "RUST_044.md"
EXPECTED_RUST043_GIT_BLOB = "786a63b9a99961efd812b562da3827614a207bfd"
ALLOWED_VERIFIER_IMPORTS = {"__future__", "hashlib", "pathlib", "sys", "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify", "rust_042_observer_journal_monitor_verify", "rust_043_monitor_set_rotation_verify"}
ALLOWED_SELFTEST_IMPORTS = {"__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile", "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify", "rust_044_multistep_monitor_rotation_verify"}


def blob(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()


def roots(src: str) -> set[str]:
    out=set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import): out.update(alias.name.split('.',1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module: out.add(node.module.split('.',1)[0])
    return out


def main() -> None:
    v=VERIFIER.read_text(); f=FIXTURE.read_text(); s=SELFTEST.read_text(); w=WORKFLOW.read_text(); d=DOC.read_text(); checks=0
    assert blob(BASE.read_bytes()) == EXPECTED_RUST043_GIT_BLOB
    assert "import rust_043_monitor_set_rotation_verify as rotation1_verify" in v
    checks+=1; print("[GREEN] exact reviewed RUST-043 verifier is composed")

    assert roots(v) <= ALLOWED_VERIFIER_IMPORTS and roots(s) <= ALLOWED_SELFTEST_IMPORTS
    for token in ("cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib", "socket", "import axven", "from axven"):
        assert token not in v and token not in s, token
    checks+=1; print("[GREEN] detached RUST-044 verifier/selftest have no private signing or network capability")

    for token in ('FINAL_SET_SEQUENCE = 2', 'rust-044-test-only-monitor-5-v1', 'CUMULATIVE_REVOKED_MONITOR_IDS', '"predecessor_rotation_sha256"', '"predecessor_rotation_auth_sha256"', '"predecessor_successor_bundle_sha256"', 'raise AssertionError("observed final monitor same-parent observer-journal fork")'):
        assert token in v, token
    checks+=1; print("[GREEN] second rotation, cumulative revocation, predecessor chain and split-view rejection are pinned")

    for token in ("permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"', "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust044-"):
        assert token in w, token
    for token in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert token not in w.lower(), token
    checks+=1; print("[GREEN] workflow stays detached, read-only and non-publishing")

    for token in ('"bb" * 32', '"cc" * 32', '"dd" * 32', '"ee" * 32', "Ed25519PrivateKey", "RUST-044 TEST-only monitor public-key pin mismatch"):
        assert token in f, token
    assert "old-rust043-final-bundle-replay" in s and "signed-final-same-parent-split-view" in s
    checks+=1; print("[GREEN] predecessor/final availability, replay rejection and producer-only private keys are pinned")

    for token in ("M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5", "cumulative revocation", "2-of-3", "TEST-only", "Production consensus remains Python-authoritative"):
        assert token in d, token
    checks+=1; print("[GREEN] documentation preserves TEST-only multi-step monitor boundary")

    assert checks == 6
    print("RUST-044 multi-step monitor rotation static policy: 6/6 checks passed")


if __name__ == "__main__": main()
