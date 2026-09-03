#!/usr/bin/env python3
"""RUST-078 static policy for TEST-ONLY RUST-077 checkpoint observation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_078.md"
VERIFY = ROOT / "rust_078_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_verify.py"
FIXTURE = ROOT / "rust_078_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_fixture.py"
SELFTEST = ROOT / "rust_078_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer.yml"
BASE = ROOT / "rust_077_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_verify.py"
EXPECTED_RUST077_GIT_BLOB = "b181383eac92bc20ea821030b23c5eed94050bd6"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_076_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_verify",
    "rust_077_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_078_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST077_GIT_BLOB
    require(
        verify,
        ("import rust_077_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_verify as journal_verify",),
        "RUST-078 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-077 verifier is composed")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-078 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "TARGET_KEYS = frozenset", "checkpoint_statement_sha256",
            "monitored_checkpoint_statement_sha256", "observed_target_sha256",
            "observed cross-observer same-parent RUST-077 monitor rotation journal checkpoint fork",
            "rotation2_verify.FINAL_PINNED_MONITORS",
        ),
        "RUST-078 verifier",
    )
    checks += 1
    print("[GREEN] exact checkpoint target, 2-of-3 quorum, and same-parent rejection are fixed")

    require(
        fixture,
        (
            '"f9" * 32', '"19" * 32', '"29" * 32', "Ed25519PrivateKey",
            "RUST-078 TEST-only journal checkpoint observer public-key pin mismatch",
        ),
        "RUST-078 producer fixture",
    )
    require(
        selftest,
        (
            "3/3 valid two-observer subsets accepted", "25/25 expected cases passed",
            "observed-cross-observer-RUST-077-monitor-rotation-journal-fork",
        ),
        "RUST-078 selftest",
    )
    checks += 1
    print("[GREEN] producer-only observer keys and 25-case availability/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust078",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test ! -e "$c/rust_078_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_fixture.py"',
            'test "$(wc -l < /tmp/axven-rust078-paths)" -eq 123',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 51',
        ),
        "RUST-078 workflow",
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
            "2-of-3", "3/3 valid two-observer subsets", "25/25 fail-closed cases",
            "exact RUST-077 final checkpoint SHA-256", "same-parent fork substitution",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-078 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only observation boundary")

    assert checks == 6
    print("RUST-078 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
