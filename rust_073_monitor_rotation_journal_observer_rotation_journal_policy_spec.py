#!/usr/bin/env python3
"""RUST-073 static policy for TEST-ONLY observer rotation journal."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal-observer-rotation-journal-v2.yml"
VERIFIER = ROOT / "rust_073_monitor_rotation_journal_observer_rotation_journal_verify.py"
SELFTEST = ROOT / "rust_073_monitor_rotation_journal_observer_rotation_journal_selftest.py"
FIXTURE = ROOT / "rust_073_monitor_rotation_journal_observer_rotation_journal_fixture.py"
BASE = ROOT / "rust_072_multistep_monitor_rotation_journal_observer_set_rotation_verify.py"
DOC = ROOT / "RUST_073.md"
EXPECTED_RUST072_GIT_BLOB = "b2b3a42fae868296fcc21aa10c1e226295eb5aa9"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_070_monitor_rotation_journal_observer_verify",
    "rust_071_monitor_rotation_journal_observer_set_rotation_verify",
    "rust_072_multistep_monitor_rotation_journal_observer_set_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_070_monitor_rotation_journal_observer_verify",
    "rust_073_monitor_rotation_journal_observer_rotation_journal_verify",
}


def text(path: Path) -> str:
    value = path.read_text(encoding="utf-8")
    if "\r" in value:
        raise AssertionError(f"CR forbidden: {path.name}")
    return value


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


def require(haystack: str, needles: tuple[str, ...], label: str) -> None:
    missing = [needle for needle in needles if needle not in haystack]
    if missing:
        raise AssertionError(f"{label} missing required markers: {missing}")


def main() -> None:
    verifier = text(VERIFIER); selftest = text(SELFTEST); fixture = text(FIXTURE)
    workflow = text(WORKFLOW); doc = text(DOC); checks = 0

    assert blob(BASE.read_bytes()) == EXPECTED_RUST072_GIT_BLOB
    require(
        verifier,
        ("import rust_072_multistep_monitor_rotation_journal_observer_set_rotation_verify as rotation2_verify",),
        "RUST-073 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-072 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-073 verifier/selftest have no signing or network capability")

    require(
        verifier,
        (
            'JOURNAL_SCHEMA = "axven-native-monitor-rotation-journal-observer-set-rotation-journal-v1"',
            'ENTRY_SCHEMA = "axven-native-monitor-rotation-journal-observer-set-rotation-journal-entry-v1"',
            'CHECKPOINT_SCHEMA = "axven-native-monitor-rotation-journal-observer-set-rotation-journal-checkpoint-v1"',
            'STATEMENT_SCHEMA = "axven-native-monitor-rotation-journal-observer-set-rotation-journal-checkpoint-statement-v1"',
            'CHECKPOINT_DOMAIN = b"AXVEN_NATIVE_MONITOR_ROTATION_JOURNAL_OBSERVER_SET_ROTATION_JOURNAL_CHECKPOINT_V1\\x00"',
            "THRESHOLD = 2", "if frozenset(target) != observer_verify.TARGET_KEYS",
            '"predecessor_entry_sha256"', '"cumulative_revoked_observer_ids"',
            'final_journal["entries"][:2] != prefix_journal["entries"]',
            "observed same-parent RUST-073 observer rotation journal checkpoint fork",
            "ids != sorted(ids)", "len(ids) != len(set(ids))",
        ),
        "RUST-073 verifier",
    )
    checks += 1
    print("[GREEN] hash-chain journal, exact target digest, prefix preservation and split-view rejection are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', 'for n in $(seq -w 36 73)',
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test ! -e "$c/rust_073_monitor_rotation_journal_observer_rotation_journal_fixture.py"',
            'test "$(wc -l < /tmp/axven-rust073-paths)" -eq 111',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 46',
        ),
        "RUST-073 workflow",
    )
    for forbidden in (
        "contents: write", "id-token: write", "packages: write", "pull-requests: write",
        "actions/upload-artifact", "attest", "release", "deploy",
    ):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, manifest-bounded and non-publishing")

    require(
        fixture,
        (
            '"d9" * 32', '"e9" * 32', '"f9" * 32', '"09" * 32',
            "Ed25519PrivateKey", "RUST-073 TEST-only observer public-key pin mismatch",
            "axven-rust073-observed-fork-observer-rotation-checkpoint.json",
        ),
        "RUST-073 producer fixture",
    )
    require(
        selftest,
        (
            "RUST-073 prefix checkpoint availability: 3/3 valid two-observer subsets accepted",
            "RUST-073 final checkpoint availability: 3/3 valid two-observer subsets accepted",
            "35/35 expected cases passed", "observed-valid-same-parent-observer-rotation-journal-fork",
        ),
        "RUST-073 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys, 3/3 availability and 35-case fail-closed matrix are fixed")

    require(
        doc,
        (
            "three monotonic entries", "O1/O2/O3 -> O2/O3/O4 -> O3/O4/O5",
            "strict 2-of-3", "3/3 valid two-observer subsets",
            "same observer-set sequence and same previous-checkpoint parent",
            "Split-view safety remains stronger than availability",
            "does **not** create global network gossip",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-073 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only append-only journal boundary")

    assert checks == 6
    print("RUST-073 observer rotation journal static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
