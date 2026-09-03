#!/usr/bin/env python3
"""RUST-106 static policy for TEST-ONLY RUST-105 checkpoint monitoring."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_106.md"
VERIFY = ROOT / "rust_106_rust105_checkpoint_monitor_verify.py"
FIXTURE = ROOT / "rust_106_rust105_checkpoint_monitor_fixture.py"
SELFTEST = ROOT / "rust_106_rust105_checkpoint_monitor_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-rust106-rust105-checkpoint-monitor.yml"
BASE = ROOT / "rust_105_rust102_checkpoint_monitor_rotation_journal_verify.py"
PREDECESSOR_WORKFLOW = ROOT / ".github/workflows/native-rust105-checkpoint-monitor-rotation-journal.yml"
EXPECTED_RUST105_GIT_BLOB = "6afc2b6310fb438e8550c1365dac18cfe742e54b"
EXPECTED_RUST105_WORKFLOW_GIT_BLOB = "88c687d7af7bc35a8b22c9e1e86317e1d2a661bb"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_105_rust102_checkpoint_monitor_rotation_journal_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_105_rust102_checkpoint_monitor_rotation_journal_verify",
    "rust_106_rust105_checkpoint_monitor_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST105_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST105_WORKFLOW_GIT_BLOB
    require(
        verify,
        ("import rust_105_rust102_checkpoint_monitor_rotation_journal_verify as journal_verify",),
        "RUST-106 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-105 verifier and workflow are pinned")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-106 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "CHECKPOINT_SHA_KEY", "CHECKPOINT_STATEMENT_SHA_KEY",
            "production RUST-106 monitoring forbidden",
            "observed monitor same-parent RUST-105 monitor rotation journal checkpoint fork",
            "monitor_set_sequence", "monitor_set_sha256", "entry_count",
            "journal_sha256", "head_entry_sha256", "previous_checkpoint_sha256",
            "monitored_checkpoint_sha256", "monitored_checkpoint_statement_sha256",
            "observed_target_sha256", "activation_source_commit",
            "base_paths[197]", "base_paths[198]", "path_args[199]",
        ),
        "RUST-106 verifier",
    )
    checks += 1
    print("[GREEN] exact 12-field RUST-105 checkpoint binding, quorum, and same-parent rejection are fixed")

    require(
        fixture,
        (
            '"3c" * 32', '"4c" * 32', '"5c" * 32', "Ed25519PrivateKey",
            "RUST-106 TEST-only monitor public-key pin mismatch",
        ),
        "RUST-106 producer fixture",
    )
    require(
        selftest,
        (
            "3/3 valid two-monitor subsets accepted",
            "signed observed same-parent fork evidence validated",
            "27/27 expected cases passed",
            "rust105-checkpoint-replay",
        ),
        "RUST-106 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and availability/replay/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust106",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            '"rust_*.py"', '"RUST_*.md"', 'printf -v n3 "%03d" "$n"',
            'test ! -e "$c/rust_106_rust105_checkpoint_monitor_fixture.py"',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 79',
            "expected 199 RUST-105 paths", "expected 200 RUST-106 paths",
            "axven-rust106-monitor-bundle.json",
        ),
        "RUST-106 workflow",
    )
    for forbidden in (
        "contents: write", "id-token: write", "packages: write", "pull-requests: write",
        "actions/upload-artifact", "attest", "release", "deploy",
    ):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, 100-boundary-safe, read-only, and non-publishing")

    require(
        doc,
        (
            "TEST-ONLY", "2-of-3", "3/3",
            "exact RUST-105 final checkpoint SHA-256",
            "same-parent", "RUST-105 checkpoint replay",
            "79-file", "200-path",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-106 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only monitoring boundary")

    assert checks == 6
    print("RUST-106 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
