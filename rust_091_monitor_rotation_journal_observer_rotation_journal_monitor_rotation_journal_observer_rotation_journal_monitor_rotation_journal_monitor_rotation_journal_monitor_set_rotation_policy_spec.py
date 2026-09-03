#!/usr/bin/env python3
"""RUST-091 static policy for TEST-ONLY RUST-090 checkpoint monitor-set rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_091.md"
VERIFY = ROOT / "rust_091_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_set_rotation_verify.py"
FIXTURE = ROOT / "rust_091_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_set_rotation_fixture.py"
SELFTEST = ROOT / "rust_091_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_set_rotation_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-monitor-rotation-journal-monitor-set-rotation.yml"
BASE = ROOT / "rust_090_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_verify.py"
PREDECESSOR_WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-monitor-rotation-journal-monitor.yml"
EXPECTED_RUST090_GIT_BLOB = "b97f0e78699d74df88458f55709ab93819ad397a"
EXPECTED_RUST090_WORKFLOW_GIT_BLOB = "d81d14a5649f34557deea6dfdec6b0adbf21607f"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_090_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_090_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_verify",
    "rust_091_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_set_rotation_verify",
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
    doc = text(DOC); verify = text(VERIFY); fixture = text(FIXTURE)
    selftest = text(SELFTEST); workflow = text(WORKFLOW); checks = 0

    assert blob(BASE.read_bytes()) == EXPECTED_RUST090_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST090_WORKFLOW_GIT_BLOB
    require(
        verify,
        ("import rust_090_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_verify as monitor_verify",),
        "RUST-091 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-090 verifier and workflow are pinned")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-091 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "OLD_SET_SEQUENCE = 0", "NEW_SET_SEQUENCE = 1",
            "REVOKED_MONITOR_ID = monitor_verify.MONITOR_1_ID",
            "predecessor_monitor_bundle_sha256", "successor_monitor_set_sequence",
            "successor_monitor_set_sha256", "observed RUST-091 successor same-parent checkpoint fork",
            "*monitor_verify.TARGET_KEYS",
        ),
        "RUST-091 verifier",
    )
    checks += 1
    print("[GREEN] exact predecessor binding, 2-of-3 rotation, revocation, and successor epoch are fixed")

    require(
        fixture,
        (
            '"fa" * 32', '"0b" * 32', '"1b" * 32', '"2b" * 32',
            "Ed25519PrivateKey", "RUST-091 TEST-only monitor public-key pin mismatch",
        ),
        "RUST-091 producer fixture",
    )
    require(
        selftest,
        (
            "predecessor authorization availability: 3/3",
            "successor monitoring availability: 3/3",
            "50/50 expected cases passed", "old-rust090-bundle-replay",
            "observed-valid-successor-same-parent-fork",
        ),
        "RUST-091 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 3/3 + 3/3 + 50/50 test matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust091",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test ! -e "$c/rust_091_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_set_rotation_fixture.py"',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 64',
            "expected 156 RUST-090 paths", "expected 159 RUST-091 paths",
            "axven-rust091-successor-monitor-bundle.json",
        ),
        "RUST-091 workflow",
    )
    for forbidden in (
        "contents: write", "id-token: write", "packages: write", "pull-requests: write",
        "actions/upload-artifact", "attest", "release", "deploy",
    ):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, manifest-bounded, and non-publishing")

    require(
        doc,
        (
            "TEST-ONLY", "M1/M2/M3 to M2/M3/M4", "2-of-3", "3/3", "50/50",
            "fixed 159-path manifest", "64-file verifier-only detached consumer",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-091 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only monitor rotation boundary")

    assert checks == 6
    print("RUST-091 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
