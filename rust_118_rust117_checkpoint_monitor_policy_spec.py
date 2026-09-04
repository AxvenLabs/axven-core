#!/usr/bin/env python3
"""RUST-118 static policy for TEST-ONLY RUST-117 checkpoint monitoring."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_118.md"
VERIFY = ROOT / "rust_118_rust117_checkpoint_monitor_verify.py"
FIXTURE = ROOT / "rust_118_rust117_checkpoint_monitor_fixture.py"
SELFTEST = ROOT / "rust_118_rust117_checkpoint_monitor_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-rust118-rust117-checkpoint-monitor.yml"
BASE = ROOT / "rust_117_rust114_checkpoint_monitor_rotation_journal_verify.py"
PREDECESSOR_WORKFLOW = ROOT / ".github/workflows/native-rust117-checkpoint-monitor-rotation-journal.yml"
EXPECTED_RUST117_GIT_BLOB = "fbafe69faf45f0eea9b650de6e33d038e970126e"
EXPECTED_RUST117_WORKFLOW_GIT_BLOB = "46f3d8d5feb4b56e9bd6d3a516871ead5c0bf20e"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_117_rust114_checkpoint_monitor_rotation_journal_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_117_rust114_checkpoint_monitor_rotation_journal_verify",
    "rust_118_rust117_checkpoint_monitor_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST117_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST117_WORKFLOW_GIT_BLOB
    require(
        verify,
        ("import rust_117_rust114_checkpoint_monitor_rotation_journal_verify as journal_verify",),
        "RUST-118 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-117 verifier and workflow are pinned")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-118 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "CHECKPOINT_SHA_KEY", "CHECKPOINT_STATEMENT_SHA_KEY",
            "production RUST-118 monitoring forbidden",
            "observed monitor same-parent RUST-117 monitor rotation journal checkpoint fork",
            "monitor_set_sequence", "monitor_set_sha256", "entry_count",
            "journal_sha256", "head_entry_sha256", "previous_checkpoint_sha256",
            "monitored_checkpoint_sha256", "monitored_checkpoint_statement_sha256",
            "observed_target_sha256", "activation_source_commit",
            "base_paths[230]", "base_paths[231]", "path_args[232]",
        ),
        "RUST-118 verifier",
    )
    checks += 1
    print("[GREEN] exact 12-field RUST-117 checkpoint binding, quorum, and same-parent rejection are fixed")

    require(
        fixture,
        (
            '"2d" * 32', '"3d" * 32', '"4d" * 32', "Ed25519PrivateKey",
            "RUST-118 TEST-only monitor public-key pin mismatch",
        ),
        "RUST-118 producer fixture",
    )
    require(
        selftest,
        (
            "3/3 valid two-monitor subsets accepted",
            "signed observed same-parent fork evidence validated",
            "27/27 expected cases passed",
            "rust117-checkpoint-replay",
        ),
        "RUST-118 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and availability/replay/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust118",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            '"rust_*.py"', '"RUST_*.md"', 'printf -v n3 "%03d" "$n"',
            'test ! -e "$c/rust_118_rust117_checkpoint_monitor_fixture.py"',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 91',
            "expected 232 RUST-117 paths", "expected 233 RUST-118 paths",
            "axven-rust118-monitor-bundle.json",
        ),
        "RUST-118 workflow",
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
            "exact RUST-117 final checkpoint SHA-256",
            "same-parent", "RUST-117 checkpoint replay",
            "91-file", "233-path",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-118 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only monitoring boundary")

    assert checks == 6
    print("RUST-118 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
