#!/usr/bin/env python3
"""RUST-070 static policy for TEST-ONLY RUST-069 checkpoint observation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal-observer.yml"
VERIFIER = ROOT / "rust_070_monitor_rotation_journal_observer_verify.py"
SELFTEST = ROOT / "rust_070_monitor_rotation_journal_observer_selftest.py"
FIXTURE = ROOT / "rust_070_monitor_rotation_journal_observer_fixture.py"
BASE = ROOT / "rust_069_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_verify.py"
DOC = ROOT / "RUST_070.md"
EXPECTED_RUST069_GIT_BLOB = "73e8617fd8a382f4b9ebeb22654d9c0391187ca9"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_068_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_verify",
    "rust_069_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_070_monitor_rotation_journal_observer_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST069_GIT_BLOB
    require(
        verifier,
        ("import rust_069_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_verify as journal_verify",),
        "RUST-070 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-069 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-070 observer verifier/selftest have no signing or network capability")

    require(
        verifier,
        (
            "THRESHOLD = 2",
            'OBSERVER_1_ID = "rust-070-test-only-monitor-rotation-journal-observer-1-v1"',
            'OBSERVER_2_ID = "rust-070-test-only-monitor-rotation-journal-observer-2-v1"',
            'OBSERVER_3_ID = "rust-070-test-only-monitor-rotation-journal-observer-3-v1"',
            'OBSERVER_1_PUBLIC_KEY = bytes.fromhex("ba3b611e2882c1b6aa4b2ae3ec78ea0736e3ad99238353450171507a4b9f15b5")',
            'OBSERVER_2_PUBLIC_KEY = bytes.fromhex("8e4190cd68fdc07dda0c59e6cb073efd2d9311d622a38a32df6885b4a4121551")',
            'OBSERVER_3_PUBLIC_KEY = bytes.fromhex("0a81997d7673889d50f91fa0cf664f1c7a6ababd03f71cf0fe5d68ad7576d337")',
            '"monitored_checkpoint_sha256"', '"monitored_checkpoint_statement_sha256"',
            '"observed_target_sha256"', "ids != sorted(ids)", "len(ids) != len(set(ids))",
            "observed cross-observer same-parent RUST-069 monitor rotation journal checkpoint fork",
        ),
        "RUST-070 verifier",
    )
    checks += 1
    print("[GREEN] 2-of-3 pins, exact target bindings, ordering and split-view rejection are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "env -i HOME=/tmp PATH=/usr/bin:/bin",
            "/usr/bin/python3 -S", "chmod 0444 /tmp/axven-rust070-*.json",
            'test ! -e "$c/rust_070_monitor_rotation_journal_observer_fixture.py"',
            'test "$(wc -l < /tmp/axven-rust070-paths)" -eq 101',
        ),
        "RUST-070 workflow",
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
            '"c9" * 32', '"d9" * 32', '"e9" * 32', "Ed25519PrivateKey",
            "RUST-070 TEST-only monitor-rotation-journal observer public-key pin mismatch",
        ),
        "RUST-070 producer fixture",
    )
    require(
        selftest,
        (
            "3/3 valid two-observer subsets accepted", "25/25 expected cases passed",
            "observed-cross-observer-RUST-069-monitor-rotation-journal-fork",
        ),
        "RUST-070 selftest",
    )
    checks += 1
    print("[GREEN] producer-only observer keys and 25-case availability/fork matrix are fixed")

    require(
        doc,
        (
            "at least 2-of-3", "3/3 valid two-observer subsets",
            "same monitor-set sequence and same previous-checkpoint parent",
            "does **not** create global network gossip", "split-view safety over availability",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-070 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only observation boundary")

    assert checks == 6
    print("RUST-070 monitor-rotation-journal observation static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
