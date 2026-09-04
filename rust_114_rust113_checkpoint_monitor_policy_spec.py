#!/usr/bin/env python3
"""RUST-114 static policy for TEST-ONLY RUST-113 checkpoint monitoring."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_114.md"
VERIFY = ROOT / "rust_114_rust113_checkpoint_monitor_verify.py"
FIXTURE = ROOT / "rust_114_rust113_checkpoint_monitor_fixture.py"
SELFTEST = ROOT / "rust_114_rust113_checkpoint_monitor_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-rust114-rust113-checkpoint-monitor.yml"
BASE = ROOT / "rust_113_rust110_checkpoint_monitor_rotation_journal_verify.py"
PREDECESSOR_WORKFLOW = ROOT / ".github/workflows/native-rust113-checkpoint-monitor-rotation-journal.yml"
EXPECTED_RUST113_GIT_BLOB = "b43655dd9ad8c76322a9a3d3d6df28a4dc4cdefb"
EXPECTED_RUST113_WORKFLOW_GIT_BLOB = "24d551bb4541a379c067013f84548db042901162"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_113_rust110_checkpoint_monitor_rotation_journal_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_113_rust110_checkpoint_monitor_rotation_journal_verify",
    "rust_114_rust113_checkpoint_monitor_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST113_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST113_WORKFLOW_GIT_BLOB
    require(
        verify,
        ("import rust_113_rust110_checkpoint_monitor_rotation_journal_verify as journal_verify",),
        "RUST-114 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-113 verifier and workflow are pinned")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-114 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "CHECKPOINT_SHA_KEY", "CHECKPOINT_STATEMENT_SHA_KEY",
            "production RUST-114 monitoring forbidden",
            "observed monitor same-parent RUST-113 monitor rotation journal checkpoint fork",
            "monitor_set_sequence", "monitor_set_sha256", "entry_count",
            "journal_sha256", "head_entry_sha256", "previous_checkpoint_sha256",
            "monitored_checkpoint_sha256", "monitored_checkpoint_statement_sha256",
            "observed_target_sha256", "activation_source_commit",
            "base_paths[219]", "base_paths[220]", "path_args[221]",
        ),
        "RUST-114 verifier",
    )
    checks += 1
    print("[GREEN] exact 12-field RUST-113 checkpoint binding, quorum, and same-parent rejection are fixed")

    require(
        fixture,
        (
            '"dc" * 32', '"ec" * 32', '"fc" * 32', "Ed25519PrivateKey",
            "RUST-114 TEST-only monitor public-key pin mismatch",
        ),
        "RUST-114 producer fixture",
    )
    require(
        selftest,
        (
            "3/3 valid two-monitor subsets accepted",
            "signed observed same-parent fork evidence validated",
            "27/27 expected cases passed",
            "rust113-checkpoint-replay",
        ),
        "RUST-114 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and availability/replay/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust114",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            '"rust_*.py"', '"RUST_*.md"', 'printf -v n3 "%03d" "$n"',
            'test ! -e "$c/rust_110_rust113_checkpoint_monitor_fixture.py"',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 87',
            "expected 221 RUST-113 paths", "expected 222 RUST-114 paths",
            "axven-rust114-monitor-bundle.json",
        ),
        "RUST-114 workflow",
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
            "exact RUST-113 final checkpoint SHA-256",
            "same-parent", "RUST-113 checkpoint replay",
            "87-file", "222-path",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-114 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only monitoring boundary")

    assert checks == 6
    print("RUST-114 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
