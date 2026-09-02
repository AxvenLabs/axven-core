#!/usr/bin/env python3
"""RUST-040 static policy for TEST-ONLY multi-step observer-set rotation continuity."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-multistep-observer-rotation.yml"
VERIFIER = ROOT / "rust_040_multistep_observer_rotation_verify.py"
FIXTURE = ROOT / "rust_040_multistep_observer_rotation_fixture.py"
SELFTEST = ROOT / "rust_040_multistep_observer_rotation_selftest.py"
BASE = ROOT / "rust_039_observer_set_rotation_verify.py"
DOC = ROOT / "RUST_040.md"
EXPECTED_RUST039_GIT_BLOB = "c15926e5d880b0392a3c9aaf80818880c5479a83"
ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_038_checkpoint_gossip_verify", "rust_039_observer_set_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_040_multistep_observer_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST039_GIT_BLOB
    assert "import rust_039_observer_set_rotation_verify as rotation1_verify" in v
    checks += 1; print("[GREEN] exact reviewed RUST-039 verifier is composed")

    assert roots(v) <= ALLOWED_VERIFIER_IMPORTS
    assert roots(s) <= ALLOWED_SELFTEST_IMPORTS
    for token in ("cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib", "socket", "import axven", "from axven"):
        assert token not in v and token not in s, token
    checks += 1; print("[GREEN] detached RUST-040 verifier/selftest have no private signing or network capability")

    for token in (
        'FINAL_SET_SEQUENCE = 2', 'rust-040-test-only-observer-5-v1',
        'CUMULATIVE_REVOKED_OBSERVER_IDS', '"predecessor_rotation_sha256"',
        '"predecessor_successor_bundle_sha256"',
        'raise AssertionError("observed final same-parent checkpoint fork")',
    ):
        assert token in v, token
    checks += 1; print("[GREEN] sequence-2 set, O5, cumulative revocation and predecessor evidence binding are pinned")

    for token in ("permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"', "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust040-second-observer-set-rotation.json"):
        assert token in w, token
    for token in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert token not in w.lower(), token
    checks += 1; print("[GREEN] workflow stays detached, read-only and non-publishing")

    for token in ('"66" * 32', '"77" * 32', '"88" * 32', '"99" * 32', "Ed25519PrivateKey", "RUST-040 TEST-only observer public-key pin mismatch"):
        assert token in f, token
    assert "rust_040_multistep_observer_rotation_fixture.py" in w
    assert "rust_040_multistep_observer_rotation_selftest.py" in w
    checks += 1; print("[GREEN] predecessor/final private observer fixtures remain producer-side")

    for token in ("O1/O2/O3 -> O2/O3/O4", "O3/O4/O5", "[O1, O2]", "does **not** create independent observer administration", "Production consensus remains Python-authoritative"):
        assert token in d, token
    checks += 1; print("[GREEN] documentation preserves TEST-only multi-step observer boundary")

    assert checks == 6
    print("RUST-040 multi-step observer rotation static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
