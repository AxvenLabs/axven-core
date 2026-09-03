#!/usr/bin/env python3
"""RUST-082 static policy for TEST-ONLY RUST-081 checkpoint monitoring."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_082.md"
VERIFY = ROOT / "rust_082_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_verify.py"
FIXTURE = ROOT / "rust_082_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_fixture.py"
SELFTEST = ROOT / "rust_082_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-rotation-journal-monitor.yml"
BASE = ROOT / "rust_081_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_verify.py"
EXPECTED_RUST081_GIT_BLOB = "d7c36514221c1c8ffdb3bc0b66fdebde6c9ee6ab"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_080_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_verify",
    "rust_081_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_080_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_verify",
    "rust_081_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_verify",
    "rust_082_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST081_GIT_BLOB
    require(
        verify,
        ("import rust_081_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_verify as journal_verify",),
        "RUST-082 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-081 verifier is composed")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-082 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2",
            "production RUST-082 observer-rotation-journal monitoring forbidden",
            "observed monitor same-parent RUST-081 observer rotation journal checkpoint fork",
            "monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_checkpoint_sha256",
            "monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_checkpoint_statement_sha256",
            "observed_checkpoint_sha256", "observed_checkpoint_statement_sha256",
            "observed_target_sha256", "activation_source_commit",
        ),
        "RUST-082 verifier",
    )
    checks += 1
    print("[GREEN] exact checkpoint bindings, 2-of-3 quorum, and same-parent rejection are fixed")

    require(
        fixture,
        (
            '"59" * 32', '"69" * 32', '"79" * 32', "Ed25519PrivateKey",
            "RUST-082 TEST-only monitor public-key pin mismatch",
        ),
        "RUST-082 producer fixture",
    )
    require(
        selftest,
        (
            "3/3 valid two-monitor subsets accepted",
            "signed observed same-parent fork evidence validated",
            "27/27 expected cases passed",
            "rust081-checkpoint-replay",
        ),
        "RUST-082 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and availability/replay/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust082",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test ! -e "$c/rust_082_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_fixture.py"',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 55',
            'test "$(wc -l < /tmp/axven-rust082-paths)" -eq 134',
        ),
        "RUST-082 workflow",
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
            "TEST-ONLY", "2-of-3", "3/3",
            "exact RUST-081 final checkpoint SHA-256",
            "same-parent", "RUST-081 checkpoint replay",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-082 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only monitoring boundary")

    assert checks == 6
    print("RUST-082 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
