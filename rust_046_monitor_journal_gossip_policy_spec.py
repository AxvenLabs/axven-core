#!/usr/bin/env python3
"""RUST-046 static policy for TEST-ONLY monitor-journal checkpoint observation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-monitor-journal-gossip.yml"
VERIFIER = ROOT / "rust_046_monitor_journal_gossip_verify.py"
SELFTEST = ROOT / "rust_046_monitor_journal_gossip_selftest.py"
FIXTURE = ROOT / "rust_046_monitor_journal_gossip_fixture.py"
BASE = ROOT / "rust_045_monitor_rotation_journal_verify.py"
DOC = ROOT / "RUST_046.md"
EXPECTED_RUST045_GIT_BLOB = "bf9418d1377b3386d0e807817b7ed895e2a8164d"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_044_multistep_monitor_rotation_verify", "rust_045_monitor_rotation_journal_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_046_monitor_journal_gossip_verify",
}


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def blob(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()


def imported_roots(source: str) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def main() -> None:
    verifier = text(VERIFIER)
    selftest = text(SELFTEST)
    fixture = text(FIXTURE)
    workflow = text(WORKFLOW)
    doc = text(DOC)
    checks = 0

    assert blob(BASE.read_bytes()) == EXPECTED_RUST045_GIT_BLOB
    assert "import rust_045_monitor_rotation_journal_verify as journal_verify" in verifier
    checks += 1
    print("[GREEN] exact reviewed RUST-045 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", ".sign(", "subprocess", "requests", "urllib",
        "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached journal-observer verifier/selftest have no signing or network capability")

    for marker in (
        'BUNDLE_SCHEMA = "axven-native-monitor-rotation-journal-checkpoint-observation-bundle-v1"',
        'STATEMENT_SCHEMA = "axven-native-monitor-rotation-journal-checkpoint-observation-statement-v1"',
        'OBSERVATION_DOMAIN = b"AXVEN_NATIVE_MONITOR_ROTATION_JOURNAL_CHECKPOINT_OBSERVATION_V1\\x00"',
        "THRESHOLD = 2",
        'OBSERVER_1_ID = "rust-046-test-only-journal-observer-1-v1"',
        'OBSERVER_2_ID = "rust-046-test-only-journal-observer-2-v1"',
        'OBSERVER_3_ID = "rust-046-test-only-journal-observer-3-v1"',
        'OBSERVER_1_PUBLIC_KEY = bytes.fromhex("d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c")',
        'OBSERVER_2_PUBLIC_KEY = bytes.fromhex("43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de")',
        'OBSERVER_3_PUBLIC_KEY = bytes.fromhex("6e32c19741f0af8260612ae99fd13d8a38944722e08964dd239738f552a6153b")',
        'raise AssertionError("observed cross-observer same-parent monitor-journal checkpoint fork")',
        'ids != sorted(ids)',
        'len(ids) != len(set(ids))',
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] 2-of-3 journal-observer quorum, pins, ordering, and split-view rejection are fixed")

    for marker in (
        "permissions:\n  contents: read", "persist-credentials: false", 'python-version: "3.13.15"',
        "env -i", "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust046-*.json",
        'test ! -e "$c/rust_046_monitor_journal_gossip_fixture.py"',
    ):
        assert marker in workflow, marker
    for forbidden in ("id-token: write", "actions/upload-artifact", "attest", "release", "deploy"):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, and non-publishing")

    for marker in (
        '"0f" * 32', '"1f" * 32', '"2f" * 32', "Ed25519PrivateKey",
        "RUST-046 TEST-only journal-observer public-key pin mismatch",
    ):
        assert marker in fixture, marker
    assert "rust_046_monitor_journal_gossip_fixture.py" in workflow
    assert "rust_046_monitor_journal_gossip_selftest.py" in workflow
    checks += 1
    print("[GREEN] deterministic journal-observer private fixtures remain producer-side")

    for marker in (
        "at least 2-of-3", "same monitor-set sequence and same previous-checkpoint parent",
        "does **not** create global network gossip", "strict fail-closed rule favors split-view safety over availability",
        "Production consensus remains Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] documentation preserves TEST-only observation and availability boundary")

    assert checks == 6
    print("RUST-046 monitor-journal observation static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
