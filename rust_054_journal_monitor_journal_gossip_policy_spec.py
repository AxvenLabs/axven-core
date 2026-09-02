#!/usr/bin/env python3
"""RUST-054 static policy for TEST-ONLY journal-monitor-journal checkpoint observation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-journal-monitor-journal-gossip.yml"
VERIFIER = ROOT / "rust_054_journal_monitor_journal_gossip_verify.py"
SELFTEST = ROOT / "rust_054_journal_monitor_journal_gossip_selftest.py"
FIXTURE = ROOT / "rust_054_journal_monitor_journal_gossip_fixture.py"
BASE = ROOT / "rust_053_journal_monitor_rotation_journal_verify.py"
DOC = ROOT / "RUST_054.md"
EXPECTED_RUST053_GIT_BLOB = "592ab6ea403884bc6ce1ae8a7324cf729416d27c"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_052_multistep_journal_monitor_rotation_verify",
    "rust_053_journal_monitor_rotation_journal_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_054_journal_monitor_journal_gossip_verify",
}


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def blob(raw: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(raw)}\0".encode("ascii") + raw
    ).hexdigest()


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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST053_GIT_BLOB
    assert (
        "import rust_053_journal_monitor_rotation_journal_verify as journal_verify"
        in verifier
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-053 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print(
        "[GREEN] detached journal-monitor-journal observer verifier/selftest "
        "have no signing or network capability"
    )

    for marker in (
        'BUNDLE_SCHEMA = "axven-native-journal-monitor-rotation-journal-checkpoint-observation-bundle-v1"',
        'STATEMENT_SCHEMA = "axven-native-journal-monitor-rotation-journal-checkpoint-observation-statement-v1"',
        'OBSERVATION_DOMAIN = b"AXVEN_NATIVE_JOURNAL_MONITOR_ROTATION_JOURNAL_CHECKPOINT_OBSERVATION_V1\\x00"',
        "THRESHOLD = 2",
        'OBSERVER_1_ID = "rust-054-test-only-journal-monitor-journal-observer-1-v1"',
        'OBSERVER_2_ID = "rust-054-test-only-journal-monitor-journal-observer-2-v1"',
        'OBSERVER_3_ID = "rust-054-test-only-journal-monitor-journal-observer-3-v1"',
        'OBSERVER_1_PUBLIC_KEY = bytes.fromhex("e5145a37d984d244ce11e69388cb36dedc828c1a277ca347d50f5076a60959e8")',
        'OBSERVER_2_PUBLIC_KEY = bytes.fromhex("248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd930")',
        'OBSERVER_3_PUBLIC_KEY = bytes.fromhex("7d59c5623dd40a74aa4d5a32ac645d3b3f95daeae4c22be25476dd6a486f7382")',
        'raise AssertionError(\n                "observed cross-observer same-parent journal-monitor-rotation-journal checkpoint fork"\n            )',
        'ids != sorted(ids)',
        'len(ids) != len(set(ids))',
    ):
        assert marker in verifier, marker
    checks += 1
    print(
        "[GREEN] 2-of-3 observer quorum, pins, ordering, and split-view rejection are fixed"
    )

    for marker in (
        "permissions:\n  contents: read",
        "persist-credentials: false",
        'python-version: "3.13.15"',
        "env -i",
        "/usr/bin/python3 -S",
        "chmod 0444 /tmp/axven-rust054-*.json",
        'test ! -e "$c/rust_054_journal_monitor_journal_gossip_fixture.py"',
    ):
        assert marker in workflow, marker
    for forbidden in (
        "id-token: write", "actions/upload-artifact", "attest", "release", "deploy"
    ):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, and non-publishing")

    for marker in (
        '"9b" * 32', '"ab" * 32', '"bb" * 32', "Ed25519PrivateKey",
        "RUST-054 TEST-only journal-monitor-journal observer public-key pin mismatch",
    ):
        assert marker in fixture, marker
    assert "rust_054_journal_monitor_journal_gossip_fixture.py" in workflow
    assert "rust_054_journal_monitor_journal_gossip_selftest.py" in workflow
    checks += 1
    print("[GREEN] deterministic observer private fixtures remain producer-side")

    for marker in (
        "at least 2-of-3",
        "same monitor-set sequence and same previous-checkpoint parent",
        "does **not** create global network gossip",
        "split-view safety over availability",
        "Production consensus remains Python-authoritative",
    ):
        assert marker in doc, marker
    checks += 1
    print("[GREEN] documentation preserves TEST-only observation boundary")

    assert checks == 6
    print(
        "RUST-054 journal-monitor-journal observation static policy: "
        "6/6 checks passed"
    )


if __name__ == "__main__":
    main()
