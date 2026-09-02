#!/usr/bin/env python3
"""RUST-060 static policy for TEST-ONLY multi-step observer-rotation-journal monitor rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-multistep-observer-rotation-journal-monitor-rotation.yml"
VERIFIER = ROOT / "rust_060_multistep_observer_rotation_journal_monitor_rotation_verify.py"
SELFTEST = ROOT / "rust_060_multistep_observer_rotation_journal_monitor_rotation_selftest.py"
FIXTURE = ROOT / "rust_060_multistep_observer_rotation_journal_monitor_rotation_fixture.py"
BASE = ROOT / "rust_059_observer_rotation_journal_monitor_set_rotation_verify.py"
DOC = ROOT / "RUST_060.md"
EXPECTED_RUST059_GIT_BLOB = "47c6f53e9993a6cb374dbeaebf941ad50c23a8c8"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys", "rust_030_stdlib_material_verify",
    "rust_032_external_monotonic_floor_verify", "rust_058_observer_rotation_journal_monitor_verify",
    "rust_059_observer_rotation_journal_monitor_set_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_058_observer_rotation_journal_monitor_verify",
    "rust_060_multistep_observer_rotation_journal_monitor_rotation_verify",
}


def text(path: Path) -> str: return path.read_text(encoding="utf-8")
def blob(raw: bytes) -> str: return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()

def roots(source: str) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import): out.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module: out.add(node.module.split(".", 1)[0])
    return out


def main() -> None:
    v = text(VERIFIER); s = text(SELFTEST); f = text(FIXTURE); w = text(WORKFLOW); d = text(DOC); checks = 0
    assert blob(BASE.read_bytes()) == EXPECTED_RUST059_GIT_BLOB
    assert "import rust_059_observer_rotation_journal_monitor_set_rotation_verify as rotation1_verify" in v
    checks += 1; print("[GREEN] exact reviewed RUST-059 verifier is composed")

    assert roots(v) <= ALLOWED_VERIFIER_IMPORTS
    assert roots(s) <= ALLOWED_SELFTEST_IMPORTS
    for token in ("cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib", "socket", "import axven", "from axven"):
        assert token not in v and token not in s, token
    checks += 1; print("[GREEN] detached RUST-060 verifier/selftest have no signing or network capability")

    for token in (
        'ROTATION_SCHEMA = "axven-native-journal-monitor-journal-observer-rotation-journal-monitor-set-rotation-v2"',
        'FINAL_BUNDLE_SCHEMA = "axven-native-journal-monitor-journal-observer-rotation-journal-checkpoint-monitor-bundle-v3"',
        "FINAL_SET_SEQUENCE = 2", "THRESHOLD = 2",
        'M5_ID = "rust-060-test-only-observer-rotation-journal-monitor-5-v1"',
        'M5_PUBLIC_KEY = bytes.fromhex("31f3322d4923d36c41c109bdb0099193187bed99942096e4926a24c77efd0d2f")',
        'raise AssertionError("predecessor monitor rotation authorization digest mismatch")',
        'raise AssertionError("predecessor successor monitor bundle digest mismatch")',
        'raise AssertionError("observed final same-parent observer-rotation-journal checkpoint fork")',
    ): assert token in v, token
    checks += 1; print("[GREEN] multi-step predecessor, cumulative revocation and split-view contracts are pinned")

    for token in ("permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"', "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust060-*.json", 'test ! -e "$c/rust_060_multistep_observer_rotation_journal_monitor_rotation_fixture.py"'):
        assert token in w, token
    for token in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"): assert token not in w.lower(), token
    checks += 1; print("[GREEN] workflow stays detached, read-only and non-publishing")

    for token in ('"e8" * 32', '"f8" * 32', '"09" * 32', '"19" * 32', "Ed25519PrivateKey", "RUST-060 TEST-only monitor public-key pin mismatch"):
        assert token in f, token
    assert "3/3 valid two-monitor subsets accepted" in s
    assert "35/35 expected cases passed" in s
    checks += 1; print("[GREEN] availability, fail-closed matrix and producer-only private keys are pinned")

    for token in ("M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5", "cumulative revocation `[M1, M2]`", "RUST-059 v2 successor bundle cannot replay", "same observer-set sequence and same previous-checkpoint parent", "Production consensus remains Python-authoritative"):
        assert token in d, token
    checks += 1; print("[GREEN] documentation preserves multi-step TEST-only monitor boundary")

    assert checks == 6
    print("RUST-060 multi-step observer-rotation-journal monitor rotation static policy: 6/6 checks passed")


if __name__ == "__main__": main()
